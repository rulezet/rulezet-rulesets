rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_78_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_78_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7b335917e7b6efbc77ed83e4e6307fe94ae4c123c27978db239fdc7b70a0128"

  strings:
    $s1 = "K?FaNG" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}