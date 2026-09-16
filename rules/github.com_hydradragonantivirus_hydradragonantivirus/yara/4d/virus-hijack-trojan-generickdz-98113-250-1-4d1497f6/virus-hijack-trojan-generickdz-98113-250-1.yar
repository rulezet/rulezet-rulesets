rule Virus_Hijack_Trojan_GenericKDZ_98113_250_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_250_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb994b4690d68a33dd290ca876db92a3b5bec57082d7451b31863acf73f9a759"

  strings:
    $s1 = "#$mOOL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}