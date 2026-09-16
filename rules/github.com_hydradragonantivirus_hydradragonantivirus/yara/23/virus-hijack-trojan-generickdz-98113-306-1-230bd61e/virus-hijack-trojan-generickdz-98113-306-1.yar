rule Virus_Hijack_Trojan_GenericKDZ_98113_306_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_306_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe47ce68a4af695308bb8ac01daa847fbe25be9c0a1636ca4abda2327be8ff04"

  strings:
    $s1 = "BLOB?\\5(" fullword ascii
    $s2 = "ruPa[." fullword ascii
    $s3 = "XH,fazE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}