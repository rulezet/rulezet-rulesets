rule Virus_Hijack_Gen_Trojan_ShellObject_dGX_aulKiep_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dGX@aulKiep_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9245b2e645bac827c2812bbb3fbd9a63672f01a3a38ce729652cb4eae49a4eb"

  strings:
    $s1 = "JiNN{." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}