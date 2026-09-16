rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_672_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_672_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bb6870e07b1152e15c82c373e441f1e44d9c4ece8e6e3dd92cefe7018d7e251"

  strings:
    $s1 = "5your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}