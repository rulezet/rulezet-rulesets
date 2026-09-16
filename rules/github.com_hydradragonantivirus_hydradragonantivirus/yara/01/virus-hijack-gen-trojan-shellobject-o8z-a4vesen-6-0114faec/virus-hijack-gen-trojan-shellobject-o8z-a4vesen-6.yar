rule Virus_Hijack_Gen_Trojan_ShellObject_o8Z_a4vesEn_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.o8Z@a4vesEn_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d938f8c3b936722aeeb99ef807dd7c3750d83962f2b26bb390a64964446e857b"

  strings:
    $s1 = "%microsoft.com/office/backup. You may not distribute the backup copy of the software. You may use it" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}