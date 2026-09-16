rule Virus_Hijack_Trojan_Agent_DQQO_152 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_152.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5779728233aca18266329c576c7deb16e200d4efce0b5c121e06f8505ea56bed"

  strings:
    $s1 = "R*America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}