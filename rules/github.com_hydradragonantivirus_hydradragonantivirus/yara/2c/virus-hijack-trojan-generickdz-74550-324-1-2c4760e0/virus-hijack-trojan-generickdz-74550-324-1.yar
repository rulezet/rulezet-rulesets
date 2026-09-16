rule Virus_Hijack_Trojan_GenericKDZ_74550_324_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_324_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7853e53a230d68862d838799293ef00935c0f7e9c0fb978edaba8ff37a5660bb"

  strings:
    $s1 = "l?JaSs" fullword ascii
    $s2 = "BoReDX" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}