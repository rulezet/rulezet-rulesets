rule Virus_Hijack_Trojan_GenericKDZ_79663_24_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab81d9e850947aedf98c8e49321b83fe51d359eed117da0685cd70f9b91fb814"

  strings:
    $s1 = ",Gyps?]" fullword ascii
    $s2 = "q]nAIS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}