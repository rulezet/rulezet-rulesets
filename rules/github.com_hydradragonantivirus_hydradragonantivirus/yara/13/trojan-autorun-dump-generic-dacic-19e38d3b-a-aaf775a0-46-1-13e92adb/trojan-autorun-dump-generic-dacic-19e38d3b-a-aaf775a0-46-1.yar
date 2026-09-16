rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_46_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_46_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ce22413e8ff7db3e4b7b42d6acb78b484cff634ff44f9a0d7e69afceec38c39"

  strings:
    $s1 = "this agreement, as well as all sums remaining unpaid for programs ordered and/or services received under this agreeme`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}