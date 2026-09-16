rule Trojan_Autorun_Trojan_GenericKDZ_94847_55_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_55_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c86c744db68c56c7a28016644e1a4c96d4c31e89467c14ae716148ef11dbddc"

  strings:
    $s1 = "xorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}