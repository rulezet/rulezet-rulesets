rule Virus_Hijack_Trojan_GenericKDZ_98113_67 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_67.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a5ecde443c035a31606a4bc9702c48e6046274d4826496c1f9f082ee81634fc"

  strings:
    $s1 = "=4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}