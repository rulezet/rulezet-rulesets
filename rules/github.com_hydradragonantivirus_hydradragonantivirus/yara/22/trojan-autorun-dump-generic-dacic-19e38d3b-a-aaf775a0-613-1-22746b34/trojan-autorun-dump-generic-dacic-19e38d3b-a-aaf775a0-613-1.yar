rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_613_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_613_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b37b8fcafa9657e6c43588ed7f4e56929060e23c9e75c923ed0b9dcbbc165354"

  strings:
    $s1 = "xpected multithread lock error" fullword wide
    $s2 = "  (fc_2): Linear(in_features=256, out_features=" fullword ascii
    $s3 = "  (fc_1): Linear(in_features=256, out_features=256, bias=True)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}