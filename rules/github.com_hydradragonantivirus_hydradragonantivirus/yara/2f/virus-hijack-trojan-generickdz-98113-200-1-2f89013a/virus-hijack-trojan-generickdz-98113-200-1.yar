rule Virus_Hijack_Trojan_GenericKDZ_98113_200_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_200_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "286048c95c58387804eec7586c9c81a723bed36733b538806ab47cbf7a5fbfb4"

  strings:
    $s1 = "-!PIPE$" fullword ascii
    $s2 = "Qs_>]hiNd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}