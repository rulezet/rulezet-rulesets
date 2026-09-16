rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_590_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_590_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67e0c25913c9274d256d07b239426af3c6194041f3f9e22e7d5796437150ee66"

  strings:
    $s1 = "-fyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}