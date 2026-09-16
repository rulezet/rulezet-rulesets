rule Virus_Hijack_Gen_Trojan_ShellObject_h8Y_auFLy0g_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8Y@auFLy0g_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ce6cbb4bdb31988be18d66bf098910d6900f5056da7ebc89a33ea2183bdef1f"

  strings:
    $s1 = "Rich!l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}