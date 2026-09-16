rule Virus_Hijack_Trojan_GenericKDZ_105924_540_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_540_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88a4015e6ac5e877f203195da5dd1f66629c34a55d0cd73eb5149f49f0a2b68f"

  strings:
    $s1 = " sLUe[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}