rule Virus_Hijack_Trojan_GenericKDZ_105924_42_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_42_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9aeb093f70c427ff988bcc23f6ca19a0cbf2fb853f20634964444cbcc63098ce"

  strings:
    $s1 = "E2!rAGA" fullword ascii
    $s2 = "o,AkRA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}