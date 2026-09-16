rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_349_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_349_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7566aaf3127db9569a55af839d4f81c404e52d9ba41917184613ee31ef30859"

  strings:
    $s1 = "must be a Qualified Educational User to use soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}