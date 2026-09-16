rule Virus_Hijack_Trojan_GenericKDZ_74550_79_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_79_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6a4841517af9a14ccd3418b6a1b3327583fff504dd5a71459db2bd119ca398b"

  strings:
    $s1 = "RL;LEEd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}