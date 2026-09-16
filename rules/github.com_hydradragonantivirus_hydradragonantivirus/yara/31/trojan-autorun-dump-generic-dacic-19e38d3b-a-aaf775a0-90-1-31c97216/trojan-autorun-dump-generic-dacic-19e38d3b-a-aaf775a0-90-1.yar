rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_90_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_90_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5fefe6e3c4e5f735077c47c54e2c60adb32d9527a395808a2309eb625d8cb91"

  strings:
    $s1 = "user minimum tabl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}