rule Virus_Hijack_Trojan_GenericKDZ_98113_340 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_340.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4aa30a169e983cdc69a60e0a65cbd6f74ee39346cf96fc755471ffcc478d23bb"

  strings:
    $s1 = "Trade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data,`" fullword ascii
    $s2 = "wassets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}