rule Virus_Hijack_Trojan_GenericKDZ_98113_240 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_240.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23547b6e65a1926a770adbdfd919994465a9046b9d12d8e291156389b75c6843"

  strings:
    $s1 = "vfunctionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}