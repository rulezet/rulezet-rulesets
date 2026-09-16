rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_117_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_117_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c60ea3f49b95603a2ddbb3ecc62b2b57a2631aff53654a6411199523ff616950"

  strings:
    $s1 = "A)Oracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}