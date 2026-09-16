rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_aWV0B1k_13_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@aWV0B1k_13_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eac874b0f88f0ef4406f372457f13ddfecef13d8a2e4e775457caeff3f75ff98"

  strings:
    $s1 = "K)MEse:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}