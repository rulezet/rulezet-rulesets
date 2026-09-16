rule Trojan_Autorun_Trojan_GenericKDZ_94847_58_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_58_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c29b96d736e83f85efded57b726ef5e8994572bf00baa974bfdb98e9075c0bb0"

  strings:
    $s1 = ">orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}