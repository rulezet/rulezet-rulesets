rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_320_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_320_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29d4cf8af27a2acd22933c77191060deadd92482ca3d6739dd2c1bcae8c7d9fc"

  strings:
    $s1 = "M2#bANd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}