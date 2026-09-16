rule Virus_Danger_Gen_Trojan_ShellObject_f8W_aKoUq3b_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.f8W@aKoUq3b_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9979176fe31b6fad0f232a6c5f6a6a92c0f09704ca11c73b3d50767cdca8bca7"

  strings:
    $s1 = "Microsoft Office Diagnostics.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}