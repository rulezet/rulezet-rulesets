rule Trojan_Autorun_Trojan_GenericKDZ_94847_76_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_76_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c4120180b34d0a3a61f55591dbc39069266e7ce5bbe92d0c87802235d36e648"

  strings:
    $s1 = "\\$71;[KINA{a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}