rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6e7dd415931a4cd0ffc256cb73a69d65a39de9ce555e81a3e201a435a139f5e"

  strings:
    $s1 = "c-hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}