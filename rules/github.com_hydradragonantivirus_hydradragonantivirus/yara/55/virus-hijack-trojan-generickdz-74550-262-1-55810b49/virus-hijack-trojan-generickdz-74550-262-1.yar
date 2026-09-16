rule Virus_Hijack_Trojan_GenericKDZ_74550_262_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_262_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a946f3b1e70b684548670e51a193bc535d490e7e1cab02c6ff6b3d57cfaff996"

  strings:
    $s1 = "94i2*darn" fullword ascii
    $s2 = "(#Unit" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}