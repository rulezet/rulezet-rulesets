rule Virus_Hijack_Trojan_GenericKDZ_103285_603 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_603.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5ef94555f5d4880f5cb37087b9ece7a4d4d93143d7a1800f522ad83e0706827"

  strings:
    $s1 = "JEst]-j" fullword ascii
    $s2 = "gEst]-j" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}