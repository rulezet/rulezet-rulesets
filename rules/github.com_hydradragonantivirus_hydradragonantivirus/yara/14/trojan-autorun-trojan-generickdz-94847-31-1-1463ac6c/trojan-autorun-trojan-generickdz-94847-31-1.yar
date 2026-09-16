rule Trojan_Autorun_Trojan_GenericKDZ_94847_31_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_31_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de4631c643b5afbb4c04b7aefec71320d90fbd8040e4a5cd19ceed5424bc4c67"

  strings:
    $s1 = "Sorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}