rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c7703205a14a1f86b3dfb0f5443ffa4eb502089ed7a2ee981eb26566d6a4b21"

  strings:
    $s1 = "Prating" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}