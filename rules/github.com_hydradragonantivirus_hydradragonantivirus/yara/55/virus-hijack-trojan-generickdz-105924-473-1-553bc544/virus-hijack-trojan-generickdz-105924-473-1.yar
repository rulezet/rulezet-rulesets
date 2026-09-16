rule Virus_Hijack_Trojan_GenericKDZ_105924_473_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_473_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce9db49821522b90950f7532f37a4925ed1e15c144e9d1518c47e7db47190db0"

  strings:
    $s1 = "/c%hoNk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}