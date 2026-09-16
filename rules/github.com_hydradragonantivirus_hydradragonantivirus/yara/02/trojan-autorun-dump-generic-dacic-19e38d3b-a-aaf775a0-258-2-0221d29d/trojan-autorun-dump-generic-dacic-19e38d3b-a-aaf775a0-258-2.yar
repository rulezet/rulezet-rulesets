rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_258_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_258_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b942246ae6a107be8e2d7c6390cfc9bd14d319f876365708d551aa3532916e3e"

  strings:
    $s1 = "a?#miST" fullword ascii
    $s2 = "pIAN>R" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}