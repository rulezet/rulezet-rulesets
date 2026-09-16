rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_228_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_228_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61515aaea9c8fa8f7aad3f9b26a3a41f9d4f773dc51956329c96e6564b8df32d"

  strings:
    $s1 = "TinE@|" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}