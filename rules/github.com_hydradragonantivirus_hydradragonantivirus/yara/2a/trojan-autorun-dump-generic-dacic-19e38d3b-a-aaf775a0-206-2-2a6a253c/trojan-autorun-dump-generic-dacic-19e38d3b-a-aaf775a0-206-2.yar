rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_206_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_206_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f96bd30309a76c53d20682379894414bc01bccb2c5788a414b0095f6f6762ed4"

  strings:
    $s1 = "He Fei Yun Biao Xin Xi Ke Ji You Xian Gong Si" fullword wide
    $s2 = "Copyright (C) 2020 He Fei Yun Biao Xin Xi Ke Ji You Xian Gong Si. All Rights Reserved." fullword wide
    $s3 = "DUFf)u" fullword ascii
    $s4 = "shOq:;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}