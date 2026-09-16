rule Virus_Hijack_Trojan_GenericKDZ_103285_869 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_869.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80c19666ce8d15235ef7238b985dda9e6dee819f77c0cefd41e9cf2f6864017e"

  strings:
    $s1 = "Lpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}