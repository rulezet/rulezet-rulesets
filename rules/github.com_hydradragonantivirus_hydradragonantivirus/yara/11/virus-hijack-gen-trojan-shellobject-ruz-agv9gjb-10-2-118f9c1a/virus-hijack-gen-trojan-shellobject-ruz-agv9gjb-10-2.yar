rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_10_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_10_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "979a271970938dbc84814888d5b501b94e80752eda1296aa9d78c45ba5acc62f"

  strings:
    $s1  = "   <description>PAOT</description>" fullword ascii
    $s2  = "Cyan!1y" fullword ascii
    $s3  = "Copyright (c) 1987-2017 by SoftMaker Software GmbH and its licensors" fullword wide
    $s4  = "FIst>;" fullword ascii
    $s5  = "M{vAGAl$" fullword ascii
    $s6  = "[1;doUM" fullword ascii
    $s7  = "hell&A" fullword ascii
    $s8  = "y/*Gurl" fullword ascii
    $s9  = "]rEdE}" fullword ascii
    $s10 = "SEAK:u" fullword ascii
    $s11 = "! DOle" fullword ascii
    $s12 = "!whun@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}