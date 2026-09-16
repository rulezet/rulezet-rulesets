rule Virus_Hijack_Trojan_GenericKDZ_98388_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b2826698ef1bd84fd2d0818c5427c0cfd4d2fd285f16567ce2297fad3d71d4e"

  strings:
    $s1 = "r]*bAnt]" fullword ascii
    $s2 = ")(wyLE" fullword ascii
    $s3 = "U0*hASp(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}