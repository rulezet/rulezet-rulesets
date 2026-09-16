rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_210_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_210_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cda724707768c492f01717cb64672923eb38d9bef388975d41f4f20956dbba8"

  strings:
    $s1 = "prime:E@" fullword ascii
    $s2 = "Remote Service Application" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}