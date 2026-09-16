rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_708_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_708_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcdd1c471883ddf313bc03d3137c48479c01890ff1ff9c241a060ba96492f284"

  strings:
    $s1 = "jof the software and a separate license for each copy. Content protected by digital rights management" fullword ascii
    $s2 = "Neve{imn}@kd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}