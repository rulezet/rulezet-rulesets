rule Virus_Hijack_Trojan_Agent_DQQO_164 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_164.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bda79a94cf36daa6a24a92c8998dd55f6afbc0262f27b84450e029e225f7bd2"

  strings:
    $s1 = "Eorders during any 12 month period." fullword ascii
    $s2 = "anSa,b[a" fullword ascii
    $s3 = "D\"SaMp" fullword ascii
    $s4 = "o;SaIp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}