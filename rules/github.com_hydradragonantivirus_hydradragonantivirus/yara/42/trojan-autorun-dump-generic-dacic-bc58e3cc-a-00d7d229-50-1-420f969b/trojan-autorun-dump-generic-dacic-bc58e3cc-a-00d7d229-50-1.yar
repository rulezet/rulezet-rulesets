rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_50_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_50_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28ede7fef36a4b1b1958da17f8bb85795610a1c35e14c41a734253e459f597be"

  strings:
    $s1 = "4hA(ThAw?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}