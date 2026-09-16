rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_183_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_183_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36dc746907920eef2aad86633a96a0e2aa119b0fc6fe69e578ee5271dd28c598"

  strings:
    $s1 = "I_controlfp_s(((void *)0), 0x00010000, 0x00030000)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}