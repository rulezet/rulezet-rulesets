rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_624_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_624_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cb63758dbd03cf1bd034d5b6044425f45884f4f211b146b8e11d39bfc03dc72"

  strings:
    $s1 = "O^Labor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}