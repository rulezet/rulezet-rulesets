rule Trojan_Danger_Trojan_GenericKD_72853156_606_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_606_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d4c06b9cfbb557b533684dfa45ae459d5f2cc1ef1ac03483520e22acf26cb33"

  strings:
    $s1 = "OMFG Studio?Operating System" fullword wide
    $s2 = "About Clock" fullword wide
    $s3 = "OMFG Studio" fullword wide
    $s4 = "OMFG All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}