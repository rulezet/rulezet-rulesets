rule Virus_Hijack_Gen_Heur_Mint_SP_Urelas_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Mint.SP.Urelas.1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5afe8732f0f655dfab6446d1df588b981283fdc2f1546228b6b5d3acabd8a2ba"

  strings:
    $s1 = "Copyright 2014 AiosfdHuisfe" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}