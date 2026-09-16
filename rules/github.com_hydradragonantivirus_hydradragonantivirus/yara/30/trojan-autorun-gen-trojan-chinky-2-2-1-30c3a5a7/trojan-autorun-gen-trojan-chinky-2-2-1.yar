rule Trojan_Autorun_Gen_Trojan_Chinky_2_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Chinky.2_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57ad9cafafb6273b9aa5163ac96a207cf9e85b078f6efd124408e5981a39055e"

  strings:
    $s1 = "l/hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}