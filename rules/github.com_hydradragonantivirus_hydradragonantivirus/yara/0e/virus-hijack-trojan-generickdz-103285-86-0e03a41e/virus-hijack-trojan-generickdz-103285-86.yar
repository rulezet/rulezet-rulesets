rule Virus_Hijack_Trojan_GenericKDZ_103285_86 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_86.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d40a3729a4b09eeed5a51e4b1dc2ded5518436ba7aa9dd55b4a8b1709953d95d"

  strings:
    $s1 = "The following software features use Internet protocols, which send to Microsoft (or" fullword ascii
    $s2 = "ACCEPT A" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}