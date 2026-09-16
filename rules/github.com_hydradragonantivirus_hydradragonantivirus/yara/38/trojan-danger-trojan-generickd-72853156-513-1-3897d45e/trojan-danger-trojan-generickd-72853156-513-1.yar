rule Trojan_Danger_Trojan_GenericKD_72853156_513_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_513_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ace4f7a6d941ee7bcf7028227576b5560f7dda13999daa2e72a8f851979dfb3"

  strings:
    $s1 = "t+ IntegratX with SO(" fullword ascii
    $s2 = "Termin*b" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}