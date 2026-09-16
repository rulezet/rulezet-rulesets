rule Trojan_Autorun_Trojan_GenericKDZ_94847_342_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_342_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15c77494828a781cf6f54223ff17e0969182950d8086489170757f36370c4fe0"

  strings:
    $s1 = "3whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}