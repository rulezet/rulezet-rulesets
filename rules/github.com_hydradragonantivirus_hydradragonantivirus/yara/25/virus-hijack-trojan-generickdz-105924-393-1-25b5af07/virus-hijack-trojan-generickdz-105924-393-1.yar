rule Virus_Hijack_Trojan_GenericKDZ_105924_393_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_393_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e401369ecb340d8b806c72784fc5af3dffd46569ea0f4387f816f743c3f0a539"

  strings:
    $s1 = "#lAze[" fullword ascii
    $s2 = "V$bIrr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}