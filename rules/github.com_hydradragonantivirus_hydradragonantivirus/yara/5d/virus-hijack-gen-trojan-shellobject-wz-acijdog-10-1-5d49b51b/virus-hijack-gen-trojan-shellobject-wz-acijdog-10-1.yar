rule Virus_Hijack_Gen_Trojan_ShellObject__WZ_aCIJdog_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@WZ@aCIJdog_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "375c1a273efa3290b09bf28c0e24e359702964fe87daf049a2c7ce273cc638b9"

  strings:
    $s1 = "Bozo&\\gV" fullword ascii
    $s2 = "Copyright (C) 2022, Cry" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}