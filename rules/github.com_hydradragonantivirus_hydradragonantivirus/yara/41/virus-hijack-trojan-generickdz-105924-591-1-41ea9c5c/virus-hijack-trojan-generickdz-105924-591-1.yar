rule Virus_Hijack_Trojan_GenericKDZ_105924_591_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_591_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "039406d61d68a40ab09f1ac671842b78d904ef905b8041c8d32bc04747a90563"

  strings:
    $s1 = "/&rIch" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}