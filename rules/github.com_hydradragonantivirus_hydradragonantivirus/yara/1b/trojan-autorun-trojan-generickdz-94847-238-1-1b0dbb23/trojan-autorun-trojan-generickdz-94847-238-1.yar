rule Trojan_Autorun_Trojan_GenericKDZ_94847_238_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_238_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d9cc78e66bf30bb9f5e322417d4b7935d6f2abc835d866b44a1eabc87c6cb0e"

  strings:
    $s1 = "~whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}