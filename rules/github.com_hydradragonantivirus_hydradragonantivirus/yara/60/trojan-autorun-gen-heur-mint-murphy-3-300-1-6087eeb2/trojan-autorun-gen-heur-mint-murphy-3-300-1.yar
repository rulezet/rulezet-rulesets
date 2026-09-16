rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_300_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_300_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b70a1829414eed6d01548e680ca108a2fb7bd3a63795d5953ad1201e53eafc4c"

  strings:
    $s1 = "!dhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}