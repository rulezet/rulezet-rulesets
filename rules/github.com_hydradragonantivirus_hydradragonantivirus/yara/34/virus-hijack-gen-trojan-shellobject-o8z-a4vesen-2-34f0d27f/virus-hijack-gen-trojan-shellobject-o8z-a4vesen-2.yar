rule Virus_Hijack_Gen_Trojan_ShellObject_o8Z_a4vesEn_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.o8Z@a4vesEn_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9ba48d8d506986449d7d2860c056b6c919a6fe64ef75428ef241cb0ee11fe45"

  strings:
    $s1 = "OK8?EOan" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}