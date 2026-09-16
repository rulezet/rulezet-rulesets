rule Virus_Hijack_Trojan_GenericKDZ_98388_186_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_186_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87b1e97a41074561f1399503a87f8388d1b851a31ea6e6216bcfc2841f7a6c04"

  strings:
    $s1 = "e?fUmY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}