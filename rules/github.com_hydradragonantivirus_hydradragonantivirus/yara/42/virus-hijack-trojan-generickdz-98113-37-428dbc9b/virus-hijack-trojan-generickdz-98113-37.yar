rule Virus_Hijack_Trojan_GenericKDZ_98113_37 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_37.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa5dddee8338bee29f1af1fd8656322d1c4648e52ed363dec61ac60dfdb616a4"

  strings:
    $s1 = "{+4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}