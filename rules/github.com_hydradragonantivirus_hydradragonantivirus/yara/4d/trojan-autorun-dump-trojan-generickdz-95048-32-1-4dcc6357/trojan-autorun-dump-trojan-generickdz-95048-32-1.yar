rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_32_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_32_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50f842a45a148b46ef3870ef987ab923bda053865529f58e6745d5b044fa908e"

  strings:
    $s1 = "usoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}