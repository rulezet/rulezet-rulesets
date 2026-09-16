rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52522f56c41b63f833c2d2b7429fb90915720128be1908e23b17ddecf3e467e5"

  strings:
    $s1 = "Version 2.1.1" fullword wide
    $s2 = "Copyright by Nego" fullword wide
    $s3 = "octahedra odeon Rossini" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}