rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e569a7cc3b4b3f29880ba942010259b8a89adad02120b2a44d574df336692ae8"

  strings:
    $s1 = "ELabor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}