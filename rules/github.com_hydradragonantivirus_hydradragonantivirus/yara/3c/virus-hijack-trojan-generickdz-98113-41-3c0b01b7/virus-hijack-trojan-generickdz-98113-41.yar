rule Virus_Hijack_Trojan_GenericKDZ_98113_41 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_41.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81fc85e4514eb9c17672bd48bfe8bf2f019d5b393c9408774209393af3ccbd27"

  strings:
    $s1 = "L4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}