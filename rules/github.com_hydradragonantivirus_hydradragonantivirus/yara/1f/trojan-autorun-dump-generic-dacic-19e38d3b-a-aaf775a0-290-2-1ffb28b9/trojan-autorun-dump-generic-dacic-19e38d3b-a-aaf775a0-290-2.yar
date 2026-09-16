rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_290_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_290_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fbb4abbd798c86fe0656db642ae14ecd5eb7b929bd72cffeb2bd577716dd278"

  strings:
    $s1 = "o\"mANk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}