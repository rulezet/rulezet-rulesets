rule Virus_Hijack_Trojan_GenericKDZ_98113_393 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_393.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c96f38bbea184022eed1c1e70d855581b683a5084e744f5f5890df66d660c848"

  strings:
    $s1 = "]O4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}