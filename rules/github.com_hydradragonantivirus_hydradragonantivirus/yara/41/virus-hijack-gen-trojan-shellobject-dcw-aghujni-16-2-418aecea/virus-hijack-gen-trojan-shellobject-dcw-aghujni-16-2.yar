rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_16_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_16_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca85928cd220bec3098137b1a56ba2ef507344cdcf382346069f4d07b4a5cf90"

  strings:
    $s1 = "7?ROBe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}