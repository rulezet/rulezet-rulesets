rule Virus_Hijack_Trojan_GenericKDZ_98113_252_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_252_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c39ba42551037ac61f36687d80e9a0cbf4658ddb03c212a41e60f6af5d929932"

  strings:
    $s1 = ";`diSC" fullword ascii
    $s2 = "3;RAAd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}