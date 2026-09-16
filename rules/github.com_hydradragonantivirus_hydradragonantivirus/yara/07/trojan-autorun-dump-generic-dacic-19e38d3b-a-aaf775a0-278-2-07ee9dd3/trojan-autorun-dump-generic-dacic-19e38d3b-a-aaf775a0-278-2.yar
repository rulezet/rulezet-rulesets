rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_278_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_278_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74487009a0e7170cf15bcfa7f5b3c3994fda58b688f40f805ebb0f87fa615081"

  strings:
    $s1 = "Sans:@r" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}