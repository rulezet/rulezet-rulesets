rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_648_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_648_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a96bc937f7b05c2caee4240a71d5796ae3605f65f5f8cd9a609e3a5394b2bd0"

  strings:
    $s1 = "Microsoft Ireland Operations Limited makes the l" fullword ascii
    $s2 = "fuGu'u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}