rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_798_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_798_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db3e5180b8f73d0e7610bb9ecec3140a0538f57a459de3238b0ef6d2c2b33c72"

  strings:
    $s1 = "&qyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}