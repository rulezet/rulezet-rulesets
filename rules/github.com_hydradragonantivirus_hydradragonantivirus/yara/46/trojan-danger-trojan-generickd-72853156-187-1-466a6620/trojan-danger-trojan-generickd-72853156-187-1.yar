rule Trojan_Danger_Trojan_GenericKD_72853156_187_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_187_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfdfe3f1c6d06d8890b5d864650807dabf92a4f8b29fbb73d9262ee65b6a3d1c"

  strings:
    $s1 = "Copyright 2014 FFSFDwdef" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}