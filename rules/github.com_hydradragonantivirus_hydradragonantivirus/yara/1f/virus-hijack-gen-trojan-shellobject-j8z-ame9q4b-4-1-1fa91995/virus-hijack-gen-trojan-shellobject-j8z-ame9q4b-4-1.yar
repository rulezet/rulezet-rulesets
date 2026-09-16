rule Virus_Hijack_Gen_Trojan_ShellObject_J8Z_ame9q4b_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.J8Z@ame9q4b_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c94e1999d62bdbe743f08b2383083a0b70b41c7a136507ea66614aaf1403dddc"

  strings:
    $s1 = "must re" fullword wide
    $s2 = "That Factlie very" fullword wide
    $s3 = "Copyright 2008, That Factlie very" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}