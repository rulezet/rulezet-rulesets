rule Trojan_Autorun_Trojan_GenericKDZ_94847_426_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_426_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd8b805cea6918c416a4e638243e2f9030bededdad1a9512cd7c37e52170c3ab"

  strings:
    $s1 = "jorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}