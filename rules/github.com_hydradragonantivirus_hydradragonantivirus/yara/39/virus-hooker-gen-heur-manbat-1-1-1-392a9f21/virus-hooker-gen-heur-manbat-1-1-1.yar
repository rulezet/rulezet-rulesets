rule Virus_Hooker_Gen_Heur_ManBat_1_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Gen.Heur.ManBat.1_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "914ed5ccf8a2d4b4fc59b8459d553ce4e9e3a0146fff9c6251bef0f80d949a52"

  strings:
    $s1 = "]foppY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}