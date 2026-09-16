rule Virus_Hijack_Trojan_GenericKDZ_105924_167 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_167.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ec8a609bc2e0a4f8441cf5976fa4adf7aeae80a9b4cba68fed22a7116e2e785"

  strings:
    $s1 = "F]stoG" fullword ascii
    $s2 = "$stoF$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}