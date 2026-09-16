rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_654_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_654_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c06c5d1678b82f2ee9c7167c093c4e8bb9caa115106e6723206bed87752e9abb"

  strings:
    $s1 = "boMicrosoft Ireland Operations Limited makes the l" fullword ascii
    $s2 = "and selling your products. Depending upon the type of industry`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}