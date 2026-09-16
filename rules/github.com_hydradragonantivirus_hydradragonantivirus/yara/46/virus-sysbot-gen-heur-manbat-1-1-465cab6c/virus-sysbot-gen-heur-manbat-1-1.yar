rule Virus_Sysbot_Gen_Heur_ManBat_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Gen.Heur.ManBat.1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e95a776d51dd523815eafcc68070613c519e7c6b286a4881a6c513022708e16c"

  strings:
    $s1 = "pAtY;(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}