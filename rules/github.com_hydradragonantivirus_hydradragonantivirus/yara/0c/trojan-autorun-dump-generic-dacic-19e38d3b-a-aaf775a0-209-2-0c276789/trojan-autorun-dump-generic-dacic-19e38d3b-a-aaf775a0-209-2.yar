rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_209_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_209_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7e5029d6258a083904d38b575acd8eee6d49226a7c12282542cd8462320dea6"

  strings:
    $s1 = "fnYJB!dabB" fullword ascii
    $s2 = ">ATmoS,y" fullword ascii
    $s3 = "TaRa*3:" fullword ascii
    $s4 = "M RAsP" fullword ascii
    $s5 = "PUlY{n" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}