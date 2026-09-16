rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_amOckRg_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@amOckRg_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f9d222959823362f5356ca1bb9dcaf9c8721fdce4f690db9605e65aa854490d"

  strings:
    $s1 = "Starting GDIPlus.EXE" fullword wide
    $s2 = "Starting GDIPlus Version 1.0" fullword wide
    $s3 = "About Starting GDIPlus" fullword wide
    $s4 = "Starting GDIPlus" fullword wide
    $s5 = "Starting GDIPlus MFC Application" fullword wide
    $s6 = "Starting GDIPlus Application" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}