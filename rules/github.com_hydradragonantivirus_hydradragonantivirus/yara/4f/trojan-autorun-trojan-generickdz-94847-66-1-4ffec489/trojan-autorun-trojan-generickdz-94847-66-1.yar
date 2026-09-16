rule Trojan_Autorun_Trojan_GenericKDZ_94847_66_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_66_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42d708c7ebb61c922b21ed139ef9005e3edf6002c3627834d4fc4c7f6d6d6475"

  strings:
    $s1 = "Multiple purchase lines may be created on either a requisition or purchase order or may be a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}