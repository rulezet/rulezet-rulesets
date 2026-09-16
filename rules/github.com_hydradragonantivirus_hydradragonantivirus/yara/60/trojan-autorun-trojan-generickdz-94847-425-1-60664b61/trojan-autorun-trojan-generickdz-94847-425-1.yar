rule Trojan_Autorun_Trojan_GenericKDZ_94847_425_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_425_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fcbef62ba8e667f01676f82a58af494142ffd7ed7bc1278874791fb4784dfa4"

  strings:
    $s1 = "q{America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}