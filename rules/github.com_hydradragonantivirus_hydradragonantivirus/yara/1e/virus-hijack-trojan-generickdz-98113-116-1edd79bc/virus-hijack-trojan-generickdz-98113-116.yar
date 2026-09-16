rule Virus_Hijack_Trojan_GenericKDZ_98113_116 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_116.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abfea3e11ca89e61a0c37c90d513cc36a8f2ab1e5d2a468ad0d242e9884a52e9"

  strings:
    $s1 = "E4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}