rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_au4JtZd_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@au4JtZd_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "859479ef0c6edacda7fe49290978c878465a5b4104b1b5280046fdc216d675ce"

  strings:
    $s1 = "!Error Download" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}