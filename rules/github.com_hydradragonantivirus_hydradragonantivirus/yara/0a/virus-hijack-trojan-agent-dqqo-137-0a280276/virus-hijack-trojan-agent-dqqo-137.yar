rule Virus_Hijack_Trojan_Agent_DQQO_137 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_137.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e331d13888af30bfb8f15a37c1241043f931f6f54cd0803b408e0a9ca35e04d"

  strings:
    $s1 = "Eorders during any 12 month period." fullword ascii
    $s2 = "anSa,b[a" fullword ascii
    $s3 = "D\"SaMp" fullword ascii
    $s4 = "o;SaIp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}