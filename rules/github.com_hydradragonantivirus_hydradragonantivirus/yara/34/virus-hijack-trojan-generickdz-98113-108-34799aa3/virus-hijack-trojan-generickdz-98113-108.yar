rule Virus_Hijack_Trojan_GenericKDZ_98113_108 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_108.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ee4a78069c817734bdba0ba4bac1a424e30753434e3bb06eaf141cd4617db2e"

  strings:
    $s1 = "[4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}