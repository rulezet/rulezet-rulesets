rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_aSl2g6j_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aSl2g6j_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af5e436b37df1625fe3e3c1f3ea0b2ad98f882962a2c717de0d2d691fda4a6fa"

  strings:
    $s1 = "P\"SPET" fullword ascii
    $s2 = "P\"SPEt*" fullword ascii
    $s3 = "XTT(SPEx" fullword ascii
    $s4 = "P\"SPEt" fullword ascii
    $s5 = "S\"SPEX" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}