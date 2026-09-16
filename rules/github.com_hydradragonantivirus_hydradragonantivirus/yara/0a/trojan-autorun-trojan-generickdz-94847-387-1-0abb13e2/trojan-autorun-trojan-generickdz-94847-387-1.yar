rule Trojan_Autorun_Trojan_GenericKDZ_94847_387_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_387_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20a2b712c71c21e7b4a1e05fe2c00bc51a0bb3da02a827bd055ec6864ba44ab3"

  strings:
    $s1 = "Morders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}