rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_amOckRg_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@amOckRg_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1d78b3f7b7558ae881853a4204c7c4acba982aa230b2d177fa6289f3e25a387"

  strings:
    $s1 = "SMB Share For DevelopmentFiles path" fullword wide
    $s2 = "Deleting SMB Share For DevelopmentFiles path" fullword wide
    $s3 = "Developer Tools Service" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}