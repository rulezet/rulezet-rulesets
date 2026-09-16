rule Virus_Hijack_Gen_Trojan_ShellObject_oSZ_aaT6Wyj_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oSZ@aaT6Wyj_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8341dbf4d5dcd9cc645c4978653f18a8d2dcf47bfaff9c4ffa8b84f2aad79c5e"

  strings:
    $s1 = "Select CommandLine from Win32_Process where Name='{0}'" fullword wide
    $s2 = "Shell Infrastructure Host" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}