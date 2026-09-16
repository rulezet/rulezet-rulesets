rule Virus_Hijack_Trojan_GenericKDZ_98113_17_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5b6f18376e161cca383090ac2a81e980b9a00737954272469addf6bfe6c2cd3"

  strings:
    $s1 = " )Yawl'" fullword ascii
    $s2 = "h$SHaD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}