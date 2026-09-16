rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_amOckRg_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@amOckRg_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71438cdfc2c71f1b9692a30fdbf3f07add3e5ad2bcc21f8eded88e6deaf0552f"

  strings:
    $s1 = "HanAgent, Version 1.0" fullword wide
    $s2 = "About HanAgent" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}