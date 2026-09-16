rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_263_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_263_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a32fe199ca01f108949016e230e1ee93f0704ed2cc19a9a8240ce54a9eb0e885"

  strings:
    $s1 = ")f(Yawp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}