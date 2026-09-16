import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_184_2_Tro_31 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_184_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_185_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c03a1db6bfbf327873c7e524f3a1dbd4661f6b1f9c58848d1531c420497de82"
    hash2       = "19835fdeabe926ae5d75109628791657cdf2d36f705399e07d896cc2faeb8ba4"

  strings:
    $s1 = "System,ID" fullword ascii
    $s2 = "Current MI" fullword ascii
    $s3 = "Count lE" fullword ascii
    $s4 = "List$OI" fullword ascii
    $s5 = "Current@3D" fullword ascii
    $s6 = "List<vI" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f9e81afd2870aaecd8ace36b2893b1d3" and (all of them)
    ) or (all of them)
}