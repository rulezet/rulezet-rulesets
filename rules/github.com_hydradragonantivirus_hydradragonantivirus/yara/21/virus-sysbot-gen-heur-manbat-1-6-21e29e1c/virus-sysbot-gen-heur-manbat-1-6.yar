rule Virus_Sysbot_Gen_Heur_ManBat_1_6 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Gen.Heur.ManBat.1_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "379a2f58b413f60577246eb59455487bf3149f0ca78b1a78e4c1034558a17960"

  strings:
    $s1 = "Np#CoCO l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}