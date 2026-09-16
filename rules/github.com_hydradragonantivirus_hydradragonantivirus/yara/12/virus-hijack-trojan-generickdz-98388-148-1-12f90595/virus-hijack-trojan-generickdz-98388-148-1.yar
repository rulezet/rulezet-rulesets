rule Virus_Hijack_Trojan_GenericKDZ_98388_148_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_148_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24681c64235b9110f01a5fef8bc50d72bacd059956f17f509a2e25c791790f95"

  strings:
    $s1 = "EyeY;h" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}