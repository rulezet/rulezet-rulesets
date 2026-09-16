rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_199_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_199_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00da03f20d41116e94fad36703d51404ab32380f3a6fdd673cd611bab0bad1b0"

  strings:
    $s1 = "O8and services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}