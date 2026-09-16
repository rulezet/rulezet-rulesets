rule Virus_Hijack_Trojan_GenericKDZ_98113_165_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_165_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c5ef344e22d0e28e0647b7610d2a889ed0318b411190e58b605e49f3392dba1"

  strings:
    $s1 = "GALA@4" fullword ascii
    $s2 = "@GYmeL'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}