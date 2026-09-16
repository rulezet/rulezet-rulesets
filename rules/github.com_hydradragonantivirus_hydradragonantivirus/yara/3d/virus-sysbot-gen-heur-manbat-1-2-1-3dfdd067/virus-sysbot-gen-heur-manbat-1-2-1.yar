rule Virus_Sysbot_Gen_Heur_ManBat_1_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Gen.Heur.ManBat.1_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45bb2895446acbb6ca7e7668a467cec5849dfa369ca5a3a5bb3b5364816911d5"

  strings:
    $s1 = "*shOO]" fullword ascii
    $s2 = "g\"dAda" fullword ascii
    $s3 = "<pAWeR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}