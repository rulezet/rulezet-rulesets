rule Virus_Hijack_Trojan_GenericKDZ_105924_79_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_79_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f29bed4ee9f7c3e1c9c3bac0c4b167031940368312df38d2c239630e176ed8f"

  strings:
    $s1 = "FEck!M" fullword ascii
    $s2 = "~2,Q&u@ARsE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}