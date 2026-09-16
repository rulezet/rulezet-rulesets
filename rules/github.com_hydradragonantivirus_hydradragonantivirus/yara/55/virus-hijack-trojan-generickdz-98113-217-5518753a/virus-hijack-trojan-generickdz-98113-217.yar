rule Virus_Hijack_Trojan_GenericKDZ_98113_217 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_217.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "939264b96ada959fc188b6eb28e7ab62688c4a257a539e4911b03f2398c624d3"

  strings:
    $s1 = "&^4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}