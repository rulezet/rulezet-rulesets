rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_389_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_389_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ee418978bd70e5baee31d0389cdac9fced7c9b219158a3cef4d58b460fd742d"

  strings:
    $s1 = "e(must be a Qualified Educational User to use soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}