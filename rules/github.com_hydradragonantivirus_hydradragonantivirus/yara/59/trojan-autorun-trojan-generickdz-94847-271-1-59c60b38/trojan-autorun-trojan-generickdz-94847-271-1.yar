rule Trojan_Autorun_Trojan_GenericKDZ_94847_271_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_271_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7b9a78d938a6677f7d8574b31076313d62a5f6fe94b5503c4593516cba6ad1d"

  strings:
    $s1 = "gbwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}