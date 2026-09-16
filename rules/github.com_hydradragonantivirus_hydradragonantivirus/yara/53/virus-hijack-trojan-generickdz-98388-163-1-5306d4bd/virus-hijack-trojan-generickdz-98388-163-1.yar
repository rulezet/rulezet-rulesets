rule Virus_Hijack_Trojan_GenericKDZ_98388_163_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_163_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66efda891ddfde42904bdce17571af1015b023af4dcb6b0222b5a980dcb1c4d9"

  strings:
    $s1 = "\"mW,foXy[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}