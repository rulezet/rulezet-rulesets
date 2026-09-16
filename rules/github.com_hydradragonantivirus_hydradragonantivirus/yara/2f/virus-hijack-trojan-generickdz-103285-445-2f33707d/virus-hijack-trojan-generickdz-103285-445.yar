rule Virus_Hijack_Trojan_GenericKDZ_103285_445 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_445.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8596c0cb23462fd91e693bf85119679b40d8e04a2f1b6187ddabc6ad4e9011ff"

  strings:
    $s1 = "\\'virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}