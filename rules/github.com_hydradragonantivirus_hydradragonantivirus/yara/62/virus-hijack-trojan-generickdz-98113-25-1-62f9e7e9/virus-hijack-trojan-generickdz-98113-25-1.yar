rule Virus_Hijack_Trojan_GenericKDZ_98113_25_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5c89c0f50e47c49e20579051b9a18159b9cc8dd238ee1944fc0fffe76736b5a"

  strings:
    $s1 = "= 3c,gyTe" fullword ascii
    $s2 = "pw?risK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}