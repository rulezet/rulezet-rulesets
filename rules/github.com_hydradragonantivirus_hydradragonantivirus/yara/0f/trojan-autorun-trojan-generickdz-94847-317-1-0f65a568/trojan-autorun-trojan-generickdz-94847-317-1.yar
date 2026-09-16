rule Trojan_Autorun_Trojan_GenericKDZ_94847_317_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_317_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecfff2a6e7fffd6458bec953c6d42584cce1149fa93519fe92030b581ec1af86"

  strings:
    $s1 = "9Sorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}