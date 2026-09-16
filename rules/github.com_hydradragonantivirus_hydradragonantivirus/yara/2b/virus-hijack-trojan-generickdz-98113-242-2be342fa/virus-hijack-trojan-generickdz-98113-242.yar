rule Virus_Hijack_Trojan_GenericKDZ_98113_242 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_242.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f43be9b822f0e8ce5e75915c6a4d6a1edee0be2d4f486fac12073941b978156"

  strings:
    $s1 = "xj4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}