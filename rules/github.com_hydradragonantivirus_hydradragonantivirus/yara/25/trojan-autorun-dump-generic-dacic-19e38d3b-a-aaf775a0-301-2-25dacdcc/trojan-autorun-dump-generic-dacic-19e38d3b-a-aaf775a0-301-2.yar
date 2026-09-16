rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_301_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_301_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9147c8b521d8d875b3f842779f2a4969a82c17e98a847ab39f9d0cd3730b190"

  strings:
    $s1 = "0,OoNt" fullword ascii
    $s2 = "wHaP L" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}