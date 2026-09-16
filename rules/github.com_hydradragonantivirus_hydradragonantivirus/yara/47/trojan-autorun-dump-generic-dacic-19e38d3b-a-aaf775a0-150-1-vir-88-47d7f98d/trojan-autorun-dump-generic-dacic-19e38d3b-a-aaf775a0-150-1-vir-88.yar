import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_150_1_Vir_88 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_150_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@a8BkLUm.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@a8BkLUm_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@a8BkLUm_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@a8BkLUm_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@a8BkLUm_4.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@a8BkLUm_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@a8BkLUm_6.vir, Virus.Hijack_Trojan.GenericKDZ.98388_241.vir, Virus.Hijack_Trojan.GenericKDZ.98388_71.vir, Virus.Hijack_Trojan.GenericKDZ.98388_95.vir, Virus.Hijack_Trojan.GenericKDZ.98388_98.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a579dfb3a5369a3652807141b04bfdc2510faac0f025124cbc2f85ac7d34b5a0"
    hash2       = "4671dfe18ded95d11ab507c972b3a08b5e70c546aca096e14d0ce2ff6b8e6199"
    hash3       = "7ae555c1b5fafb1a266bbd4d15b0abd9551eccfe710a199518994a8f6c78a293"
    hash4       = "aab06a7f1cd72d1b6996cff0c4660752b4276f07f21d637bfa77154f3c2c4280"
    hash5       = "cd8085a2314b9e2b91e00df1be9a28c785f972a5217c26d60ee57d0b2ce361e5"
    hash6       = "67b0ca658c561df2abc229a43465aa47d20da27d97cf77a2106ba28d3f73b2b3"
    hash7       = "68c9c0a11d0ab0e7ddbb83cf83c0f4e2b5b9f0473fbc2881af1a84451e88954b"
    hash8       = "56513ad1c029ea57666b3f40debfd6f522ba8d9b180dcf4a578927bee0cae175"
    hash9       = "7ae7287541318fc013e77448154d6583264f817c4afc3b02e894c5ee3664208d"
    hash10      = "063cd53872c5e85adf9328d3094426dc67aea399893eb8d828e257a4fe3861b9"
    hash11      = "a9804967f2643ad9f69c9e9a500b6049625253b3107a1614c13df05b0debf745"
    hash12      = "7cb089284ca2e5c818a9028cd573ea5d4881e4c87156f3087d68d344edd8afc8"

  strings:
    $s1 = " MultiPoint Connector " fullword ascii
    $s2 = "!MultiPoint Server " fullword ascii
    $s3 = "-MultiPoint Server " fullword ascii
    $s4 = "OMultipoint Server " fullword ascii
    $s5 = "^MultiPoint Server " fullword ascii
    $s6 = " Windows MultiPoint Server " fullword ascii
    $s7 = " MultiPoint Server " fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "c2a87fabf96470db507b2e6b43bd92eb" and (all of them)
    ) or (all of them)
}