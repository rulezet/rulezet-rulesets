rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_123_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_123_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54a4d563d5cdc1d2afb2f087b3efb5f107c96c1c27b17364941b963c413c2b86"

  strings:
    $s1 = "\\TLabor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}