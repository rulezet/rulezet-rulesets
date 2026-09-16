rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_716_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_716_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa575568187803398f929bfa5924fed780381528ab91a31b7cc4b09c677c54f2"

  strings:
    $s1 = "ZLabor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}