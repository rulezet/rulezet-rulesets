rule Trojan_Autorun_Trojan_GenericKDZ_94847_19_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36dcec24f98d3edda2daa3a27bf3ccaa6d026dbc5602ca177221a7fb6d50b892"

  strings:
    $s1 = "4Orders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}