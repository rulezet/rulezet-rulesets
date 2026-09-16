rule Trojan_Danger_Trojan_GenericKD_72677122_119_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_119_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22475171eb086bf67c8f5482499f8b2c6e042f169638ea44f6dbb03cf4cb20da"

  strings:
    $s1 = "it's infected by a Virus or cracked. This file won't work anymore." fullword ascii
    $s2 = "File corrupted!. This program has been manipulated and maybe" fullword ascii
    $s3 = "o<FrOe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}