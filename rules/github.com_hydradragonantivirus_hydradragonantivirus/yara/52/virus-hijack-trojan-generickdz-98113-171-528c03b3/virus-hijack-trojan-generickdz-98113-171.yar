rule Virus_Hijack_Trojan_GenericKDZ_98113_171 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_171.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "966f8aa0ccbf65e011bbbce9414bf4d7845fc6f01cb5b555bfac6cba10ec700c"

  strings:
    $s1 = "$4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}