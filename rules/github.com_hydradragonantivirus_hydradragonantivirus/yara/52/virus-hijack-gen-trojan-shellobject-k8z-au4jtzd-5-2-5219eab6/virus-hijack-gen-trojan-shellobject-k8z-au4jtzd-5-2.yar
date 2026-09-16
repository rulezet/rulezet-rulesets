rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_au4JtZd_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@au4JtZd_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4849c7a93ffa6869c9abb99bfee4c64fb1d5b37307ebed094069bd2596598af0"

  strings:
    $s1 = "dupE`cl*" fullword ascii
    $s2 = "dupe`cl*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}