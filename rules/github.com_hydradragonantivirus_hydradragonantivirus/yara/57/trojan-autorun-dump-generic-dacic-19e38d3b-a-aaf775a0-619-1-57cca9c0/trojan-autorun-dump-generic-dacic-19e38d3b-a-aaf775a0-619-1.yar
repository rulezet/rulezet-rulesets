rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_619_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_619_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b157be612c4231ae95216fe594f034f2644cc63c400f4a0b40b4b24b893deae"

  strings:
    $s1 = "0If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}