rule Virus_Hijack_Gen_Trojan_ShellObject_h8Y_auFLy0g_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8Y@auFLy0g_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab0c6f6ca31b4332e13bfea2d9e871733a53cf63acd4d9048747ac4b3370b782"

  strings:
    $s1 = "Rich!l" fullword ascii
    $s2 = "E(TUFf" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}