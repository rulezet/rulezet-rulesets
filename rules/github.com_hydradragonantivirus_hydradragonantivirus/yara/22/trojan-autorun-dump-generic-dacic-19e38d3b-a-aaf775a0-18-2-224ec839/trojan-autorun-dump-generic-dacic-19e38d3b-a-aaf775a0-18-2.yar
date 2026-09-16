rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_18_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_18_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38ef1f7a243e9cdafc4585e6b6396b0b077c7e212d8bcab4b2310de159208a8a"

  strings:
    $s1 = "d\"}cHit;DP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}