import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_278_2_Vir_382 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_278_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aOU94xe_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aOU94xe_2_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_16_1.vir, Virus.Sysbot_Trojan.GenericKD.71671752_28_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12753e984aa4edc41ac1d88b8d945f38b0f6cf423228a6bae4d458ca026d9f38"
    hash2       = "c365cd19fff926fa4a4b6b7be016683016745ec60bf5f7d859900c1e5fd9c1a0"
    hash3       = "761f31a496534520a7faaa29550442f664d7acd2ebd638a95a826cda947fe1a6"
    hash4       = "24904b80237b8918863b22dde6b22a427c5edaf59101ec91d1c95d8bea92555e"
    hash5       = "015a79ce3e8e7b7178f230aafd2d56323c1273cebc2f17b8fae94ff7f7aaacd6"

  strings:
    $s1 = "Example;component/view/dynamicgridusercontrol.xaml" fullword wide
    $s2 = "clr-namespace:Simulation" fullword ascii
    $s3 = "Drawer`1" fullword ascii
    $s4 = "World`1" fullword ascii
    $s5 = "Behaviour`1" fullword ascii
    $s6 = "local clr-namespace:Simulation.CellGUI" fullword ascii
    $s7 = "local clr-namespace:Simulation.GridGUI" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (all of them)
    ) or (all of them)
}