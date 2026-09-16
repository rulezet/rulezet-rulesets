rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_238_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_238_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a09e80f2d851b20b03a7e609ee44f1d31e34641893c5f340f3040a0a311a3d6c"

  strings:
    $s1 = "3)USEr&[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}