rule Virus_Hijack_Trojan_GenericKDZ_98113_233_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_233_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e321be2999b0d11bd0158684de3cf44296e90347b4a1e0755247427870efaa6"

  strings:
    $s1 = "skiL`U" fullword ascii
    $s2 = " *scuN" fullword ascii
    $s3 = "Deny{[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}