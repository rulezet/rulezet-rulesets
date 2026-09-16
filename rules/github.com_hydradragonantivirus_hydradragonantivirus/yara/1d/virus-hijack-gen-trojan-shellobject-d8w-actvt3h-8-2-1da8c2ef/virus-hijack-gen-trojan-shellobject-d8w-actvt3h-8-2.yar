rule Virus_Hijack_Gen_Trojan_ShellObject_D8W_aCtVt3h_8_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.D8W@aCtVt3h_8_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45570645448fd375104e1130d0427431dea5342f5f2ee0a88269e77f0b783315"

  strings:
    $s1 = "Y/?rIDE&Gb" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}