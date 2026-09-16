rule Virus_Hijack_Trojan_GenericKDZ_105924_418_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_418_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfdd34035b494a3a4a78aa4af2f8942f163190154b0b799bda6ecb0a790e43f5"

  strings:
    $s1 = "S]RIMY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}