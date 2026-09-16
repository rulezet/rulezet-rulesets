rule Virus_Hijack_Gen_Trojan_ShellObject_C8Z_amCvSwc_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.C8Z@amCvSwc_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd799c0ff5eccb26bf7814148b42032e8506e179b3b9f3dd5e86aed614ffa355"

  strings:
    $s1 = "VARA:w<Rg\\B" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}