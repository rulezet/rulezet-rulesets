rule Virus_Hijack_Trojan_GenericKDZ_98113_255 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_255.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46d2431990c0812bc0385c85e4e51f176992de4ef9478d476027b80094476aba"

  strings:
    $s1 = "Hosted Named User: is defined as an individual authorized by " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}