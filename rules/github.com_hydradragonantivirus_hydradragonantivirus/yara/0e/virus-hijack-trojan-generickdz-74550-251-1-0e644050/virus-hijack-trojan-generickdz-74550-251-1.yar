rule Virus_Hijack_Trojan_GenericKDZ_74550_251_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_251_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bb467f8a6d40449db521091fa836e4a466d91212feaaf1bba5cb5bd2badbd20"

  strings:
    $s1 = "9:fEEL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}