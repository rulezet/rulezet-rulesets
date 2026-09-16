rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30a9b0050c8bbca1fdb4b782d0622bc5aa689cc742b32cad0dde74684b3f1156"

  strings:
    $s1 = "DEDo#1i" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}