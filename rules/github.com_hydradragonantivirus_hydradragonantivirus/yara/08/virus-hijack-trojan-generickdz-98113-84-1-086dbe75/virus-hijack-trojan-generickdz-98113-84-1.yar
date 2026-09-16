rule Virus_Hijack_Trojan_GenericKDZ_98113_84_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_84_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74898445054e333ecc80a00f6f618c3ee0402b7b6a8e3b90ff63ec5adfb225df"

  strings:
    $s1 = "KElL$Drr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}