rule Virus_Hijack_Trojan_Agent_DQQO_210 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_210.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad723e2015b66c1b1a78cd5381a19c7e63357428387dcf9cc4103d99994c3d55"

  strings:
    $s1 = "Eorders during any 12 month period." fullword ascii
    $s2 = "anSa,b[a" fullword ascii
    $s3 = "D\"SaMp" fullword ascii
    $s4 = "o;SaIp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}