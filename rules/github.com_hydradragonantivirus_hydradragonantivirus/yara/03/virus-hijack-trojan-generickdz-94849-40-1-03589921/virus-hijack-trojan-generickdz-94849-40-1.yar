rule Virus_Hijack_Trojan_GenericKDZ_94849_40_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_40_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94ff402465226da378fc7f61973f438266cc05c371b35e46d59c1f315f17e235"

  strings:
    $s1 = "w,>COrM&" fullword ascii
    $s2 = "VetO {" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}