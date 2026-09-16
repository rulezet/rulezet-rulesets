rule Virus_Hijack_Trojan_GenericKDZ_79663_81_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_81_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd0aef2295f8dd35df2a39a8501b2c624b813a801ea2649fb4768b7ec75b2549"

  strings:
    $s1 = "SAnK<D" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}