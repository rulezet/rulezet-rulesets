rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_29_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_29_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a11d10202121e1817e3905e7ca11c0a57a971255f74660cc01eb7a0622e850f2"

  strings:
    $s1 = "jOLL&G" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}