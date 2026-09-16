rule Virus_Hijack_Trojan_GenericKDZ_98113_406 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_406.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "928f570bc8fa85bdc1a1ba14f563e090cd00f28b5de1bdb7f544b0c40e6e9671"

  strings:
    $s1 = "<4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}