rule Virus_Sysbot_Gen_Heur_ManBat_1_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Gen.Heur.ManBat.1_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d4cf25cce2a147cdd979dc232c2740eead57bffa86e0ed7185215ac3594f795"

  strings:
    $s1 = "drUM!M" fullword ascii
    $s2 = "Q:DINT" fullword ascii
    $s3 = ";!APII" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}