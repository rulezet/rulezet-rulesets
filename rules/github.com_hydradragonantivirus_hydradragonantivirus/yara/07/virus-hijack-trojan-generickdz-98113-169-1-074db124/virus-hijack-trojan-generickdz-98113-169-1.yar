rule Virus_Hijack_Trojan_GenericKDZ_98113_169_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_169_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b42dc5cbc19791bf3f866ee3a1ace6ee733072cf02449e1c7b7cae303e0af768"

  strings:
    $s1 = "\\[G!yawn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}