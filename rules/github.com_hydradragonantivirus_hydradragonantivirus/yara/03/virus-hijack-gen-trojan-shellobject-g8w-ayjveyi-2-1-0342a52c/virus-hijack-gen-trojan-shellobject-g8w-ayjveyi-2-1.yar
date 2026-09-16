rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5acada3fa64635f182e991ea87b8d3bcc3882cd80fb6e6b51a33ee2314de73b6"

  strings:
    $s1 = "Entwine" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}