rule Trojan_Autorun_Trojan_GenericKDZ_94847_124_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_124_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f48cc42a26165ae02530d09c8c16c873f2ea584d22225d009eb048453d31656"

  strings:
    $s1 = "htauthorized sources. Certain upgrades, support, and other services may be offered only to users of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}