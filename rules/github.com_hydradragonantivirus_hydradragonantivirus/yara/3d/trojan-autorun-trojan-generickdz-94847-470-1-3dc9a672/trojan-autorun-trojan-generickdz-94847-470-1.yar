rule Trojan_Autorun_Trojan_GenericKDZ_94847_470_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_470_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac2a68a2eb1150f2db6796abe0c32babe7d908fd3167684d2b63b4cec165bdc4"

  strings:
    $s1 = "\\IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}