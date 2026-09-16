rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aWlu0Qk_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aWlu0Qk_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "daafb7eb8c4a0630e955dbde86d29da2a14a15707cd9e71e8cd08931b9c4f04e"

  strings:
    $s1 = "*@sUji" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}