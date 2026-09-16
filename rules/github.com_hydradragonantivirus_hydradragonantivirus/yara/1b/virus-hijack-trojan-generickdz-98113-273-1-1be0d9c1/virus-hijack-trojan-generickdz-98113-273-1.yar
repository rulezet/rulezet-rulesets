rule Virus_Hijack_Trojan_GenericKDZ_98113_273_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_273_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "940a825ebb05f54e41004c5d59b5ca35ec73e36784277b5d916a48d85b797a75"

  strings:
    $s1 = "a[lied." fullword ascii
    $s2 = "W!NAUT" fullword ascii
    $s3 = "?duMb'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}