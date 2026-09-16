rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_29_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_29_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3acd01d97d183fe697a53e44f8b2ad4329bacb673843f7954b14c1327cccd38a"

  strings:
    $s1 = "Henry&&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}