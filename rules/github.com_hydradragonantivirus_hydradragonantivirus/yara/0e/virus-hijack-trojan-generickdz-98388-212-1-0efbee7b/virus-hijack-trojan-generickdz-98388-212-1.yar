rule Virus_Hijack_Trojan_GenericKDZ_98388_212_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_212_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c3c62b0589afcf99b5e3928fc40e79c65632fad3fc6b33e74a6619a6ea99860"

  strings:
    $s1 = "B*}maUx" fullword ascii
    $s2 = ",leaK I" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}