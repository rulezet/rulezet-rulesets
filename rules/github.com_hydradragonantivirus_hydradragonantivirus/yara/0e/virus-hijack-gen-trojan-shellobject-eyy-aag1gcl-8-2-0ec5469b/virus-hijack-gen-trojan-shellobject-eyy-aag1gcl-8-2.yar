rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aag1Gcl_8_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aag1Gcl_8_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "074c485967fa1a356f14c49ecb49fdfe19833b5401bd727daca572cd2d5b9794"

  strings:
    $s1 = "Copyright 2010-2017 Adobe Systems Incorporated.  All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}