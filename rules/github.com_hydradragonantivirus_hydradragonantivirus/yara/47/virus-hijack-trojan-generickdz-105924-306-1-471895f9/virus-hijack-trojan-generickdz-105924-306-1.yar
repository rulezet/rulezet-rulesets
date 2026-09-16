rule Virus_Hijack_Trojan_GenericKDZ_105924_306_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_306_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "720abbc50a85cf1fee52ac390a4414eb5624f850a8f0ca4862fd7fc77b3e174d"

  strings:
    $s1 = "WORe$]" fullword ascii
    $s2 = "-{Faon" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}