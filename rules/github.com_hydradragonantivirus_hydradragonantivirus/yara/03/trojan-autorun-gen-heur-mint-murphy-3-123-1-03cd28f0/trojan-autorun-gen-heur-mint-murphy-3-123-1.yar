rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_123_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_123_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ca746ea996f7956f3675463a5967aa4338dee6c54a2476b9b6f8e6566a61134"

  strings:
    $s1 = "Lata(V4" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}