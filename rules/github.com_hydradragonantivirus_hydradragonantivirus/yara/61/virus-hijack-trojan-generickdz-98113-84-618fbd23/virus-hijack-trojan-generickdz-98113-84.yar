rule Virus_Hijack_Trojan_GenericKDZ_98113_84 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_84.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5ea7fdbcd14037bc574e84dc038d22de5f558f30a205dbdc73f042de3afabfc"

  strings:
    $s1 = "l4. Language Packs and Proofing Tools. If you acq" fullword ascii
    $s2 = ",k]KatH" fullword ascii
    $s3 = "%k]KatH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}