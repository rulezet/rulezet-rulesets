rule Virus_Hijack_Gen_Trojan_ShellObject_4yZ_aSgChKg_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.4yZ@aSgChKg_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2e374425eb2203bbd3915e9c7cd8d3a172fb683adb48a5a5fba17770586f825"

  strings:
    $s1 = "gram Files\\(7" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}