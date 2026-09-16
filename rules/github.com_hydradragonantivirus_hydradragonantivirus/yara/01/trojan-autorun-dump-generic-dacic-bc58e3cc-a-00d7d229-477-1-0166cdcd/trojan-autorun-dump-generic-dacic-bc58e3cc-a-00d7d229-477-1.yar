rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_477_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_477_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d028058e615dc7b29b4f09bdb64c384d12972740d4f2c2bbcccabcd57014874"

  strings:
    $s1 = "P6Labor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}