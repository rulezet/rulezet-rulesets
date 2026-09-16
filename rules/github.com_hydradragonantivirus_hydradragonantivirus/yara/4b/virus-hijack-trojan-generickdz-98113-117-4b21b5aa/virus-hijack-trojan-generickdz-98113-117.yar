rule Virus_Hijack_Trojan_GenericKDZ_98113_117 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_117.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dfc7dc7d88526f8ed93884ec67a426f74e016e3003478b6b74218391189b3a1"

  strings:
    $s1 = "`4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}