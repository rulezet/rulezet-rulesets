rule Virus_Hijack_Trojan_GenericKDZ_98388_101_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_101_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4633b15a1a9744da0b53a2aef0d6fa16d1ac06fd1b9d08bd25f4c5c3d24242a3"

  strings:
    $s1 = "$slUT&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}