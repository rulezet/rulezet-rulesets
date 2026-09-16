rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b69d373340bdd8dde8c718286c5f2bb8e1bbfc0c817f0fc7d5b1b712e4ef85ff"

  strings:
    $s1 = "!This -7Afram cannot be run in DOS mode." fullword ascii
    $s2 = "Reinhabit" fullword wide
    $s3 = "Star Force" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}