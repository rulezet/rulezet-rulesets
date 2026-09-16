rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1573fd5048244f5d980ccb8c8b8f0abb4bd10fbb0e3b540bd860dc91e361f4ef"

  strings:
    $s1 = "Scowder" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}