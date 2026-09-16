rule Virus_Hijack_Trojan_GenericKDZ_98113_60 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_60.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47db14b013e7e82968e7b82b4fc2633696f8165440dc9c5a2151622d5ff67fd9"

  strings:
    $s1 = "kR4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}