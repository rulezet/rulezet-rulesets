rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_286_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_286_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4eb20d7ea61ee6008d4deae5016ff58e7dc48f887a0c83fc340a55b4020caf18"

  strings:
    $s1 = "MuLT?;" fullword ascii
    $s2 = "HUSk 3" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}