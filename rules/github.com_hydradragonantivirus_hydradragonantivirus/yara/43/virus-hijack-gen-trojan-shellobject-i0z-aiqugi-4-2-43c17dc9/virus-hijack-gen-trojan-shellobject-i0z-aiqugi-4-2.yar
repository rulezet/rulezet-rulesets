rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9155f7fae50e6c819d9d703e153f47ea14eee6ce55489fa3d788c2eec66da357"

  strings:
    $s1 = "SMB Share For DevelopmentFiles path" fullword wide
    $s2 = "Deleting SMB Share For DevelopmentFiles path" fullword wide
    $s3 = "Developer Tools Service" fullword wide
    $s4 = "=)bAsh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}