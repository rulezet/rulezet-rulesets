rule Virus_Sysbot_Gen_Heur_ManBat_1_3 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Gen.Heur.ManBat.1_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e50d7ad566a686b41e424bd7c25ac0819bd314cd5ac115624dff64703b538fa"

  strings:
    $s1 = "pAtY;(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}