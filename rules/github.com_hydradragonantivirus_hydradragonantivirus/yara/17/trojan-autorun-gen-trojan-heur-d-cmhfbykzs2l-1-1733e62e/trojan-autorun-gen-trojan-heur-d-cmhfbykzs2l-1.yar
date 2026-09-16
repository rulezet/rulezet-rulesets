rule Trojan_Autorun_Gen_Trojan_Heur_D_cmHfbykzS2l_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Heur.D.cmHfbykzS2l_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51a982f3947548bddbdfddf85768a5bf2c295a10bcfdadad331101d14c58adc8"

  strings:
    $s1 = "microsoft.com/office/backup. You may not distribute the backup co" fullword ascii
    $s2 = "e option to convert your trial rights to subscription or" fullword ascii
    $s3 = "a third party without restriction on the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}