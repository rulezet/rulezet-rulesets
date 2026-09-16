rule Virus_Hijack_Trojan_GenericKDZ_94849_17_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4ca6d8968bc592558d7f54942ceb4317b7974adef0f463f8337898192af9fae"

  strings:
    $s1 = "':mIan " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}