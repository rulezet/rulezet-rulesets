rule Virus_Hijack_Trojan_GenericKDZ_105924_490_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_490_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ef588eb204df8bb8a7a227a6c5c045471936f80b8cd47254af156d76b89d71b"

  strings:
    $s1 = "Na@OPuS" fullword ascii
    $s2 = "P(Gawm" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}