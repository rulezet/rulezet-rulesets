rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_760_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_760_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "106e70d7d28e01feea5afa704bb96323278300e1f78e2067823ee9fc246fe8ba"

  strings:
    $s1 = "7your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}