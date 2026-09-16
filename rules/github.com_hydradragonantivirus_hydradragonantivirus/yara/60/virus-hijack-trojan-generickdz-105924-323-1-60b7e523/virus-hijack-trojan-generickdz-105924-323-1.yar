rule Virus_Hijack_Trojan_GenericKDZ_105924_323_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_323_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6181566696f3f0651df434567f2173f82e444b4c502690ac0bfcf937725be46"

  strings:
    $s1 = "~]%bOat " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}