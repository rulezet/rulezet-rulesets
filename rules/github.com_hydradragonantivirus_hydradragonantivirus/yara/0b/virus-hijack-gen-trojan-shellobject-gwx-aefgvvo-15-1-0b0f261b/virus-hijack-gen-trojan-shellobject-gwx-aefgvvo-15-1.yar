rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82defdedf2d29535739e6ce09e828a6500883b6f00b116ddca1b6f656c533dfb"

  strings:
    $s1 = "Prevue" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}