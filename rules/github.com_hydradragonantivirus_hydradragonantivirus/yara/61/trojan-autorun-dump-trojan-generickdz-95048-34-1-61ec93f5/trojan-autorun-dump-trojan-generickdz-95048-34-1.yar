rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_34_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_34_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15748e60ce7a645b21e3b1d13a1f9aba2ff283c8994830ea245cff8c51edc3b7"

  strings:
    $s1 = "Psoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}