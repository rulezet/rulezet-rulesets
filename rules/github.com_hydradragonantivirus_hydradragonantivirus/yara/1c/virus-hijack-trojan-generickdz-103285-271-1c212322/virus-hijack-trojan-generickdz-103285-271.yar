rule Virus_Hijack_Trojan_GenericKDZ_103285_271 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_271.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64cbe98951b628b62fde642d61b82667bac6218ca5cfb91a55501cc7c945ef2d"

  strings:
    $s1 = "nSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}