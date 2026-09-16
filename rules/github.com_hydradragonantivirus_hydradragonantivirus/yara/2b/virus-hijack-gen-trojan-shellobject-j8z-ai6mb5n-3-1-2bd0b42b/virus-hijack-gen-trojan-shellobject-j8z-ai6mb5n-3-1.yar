rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_ai6MB5n_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@ai6MB5n_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fe7d50be8dc280587e381daa4c2d5140078178c925c991f3656bbdc3aab1688"

  strings:
    $s1 = "must re" fullword wide
    $s2 = "That Factlie very" fullword wide
    $s3 = "Copyright 2008, That Factlie very" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}