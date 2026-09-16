rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_39_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_39_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e18d499a84f01b7ee91946012afb4b83d7ca1c05960843a344ab5471a9b8cdcc"

  strings:
    $s1 = "@*\\AE:\\Program Files\\Microsoft Visual Studio\\VB98\\virus.vbp" fullword wide
    $s2 = "Set CDAudio Door Closed Wait" fullword wide
    $s3 = "C:\\Program Files\\Internet Explorer" fullword wide
    $s4 = "Set CDAudio Door Open Wait" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}