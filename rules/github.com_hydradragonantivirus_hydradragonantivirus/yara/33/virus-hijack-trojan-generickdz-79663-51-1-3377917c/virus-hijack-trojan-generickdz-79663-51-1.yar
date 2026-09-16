rule Virus_Hijack_Trojan_GenericKDZ_79663_51_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_51_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ec863e8eeb22cc7752fef5ae819fc00ce17565ad8c9863e16ca222cd078aecd"

  strings:
    $s1 = "WAnE;+" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}