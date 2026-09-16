rule Virus_Hijack_Trojan_GenericKDZ_98113_57_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_57_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b42506fc8bd3ba3900dd5777c4f5bc91e90d43416366bc472e09c008916a3ddf"

  strings:
    $s1 = "@yUTu*nP" fullword ascii
    $s2 = "7@griD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}