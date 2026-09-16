rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_1_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f87c76ce50c25cbd35a4ba2309ac20508300b2aa7e8432b1f6c5ed414409c45b"

  strings:
    $s1 = "mpa\"String" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}