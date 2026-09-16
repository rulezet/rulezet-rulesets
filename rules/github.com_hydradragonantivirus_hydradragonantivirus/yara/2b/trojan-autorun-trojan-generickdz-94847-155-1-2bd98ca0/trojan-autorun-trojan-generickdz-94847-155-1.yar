rule Trojan_Autorun_Trojan_GenericKDZ_94847_155_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_155_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6d437eacd540066dc2ea7028c8d34e8f76dd453d14d47ef15a18c19395505db"

  strings:
    $s1 = ">=authorized sources. Certain upgrades, support, and other services may be offered only to users of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}