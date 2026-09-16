rule Virus_Hijack_Trojan_GenericKDZ_103285_637 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_637.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "102abcbdbb3d6b1233d48932985dcf076a7f036cb4d285680fc1d94fa1cfc787"

  strings:
    $s1 = "Sdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}