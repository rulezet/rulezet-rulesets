rule Virus_Hijack_Trojan_GenericKDZ_98113_127 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_127.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ae8c19472dccb9166991a793c9e3383f6c9ea145fd5f987ecd867e199eaaf54"

  strings:
    $s1 = "]s4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}