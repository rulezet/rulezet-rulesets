rule Virus_Hijack_Trojan_GenericKDZ_105924_160_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_160_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34aabc3f2323462bfd3401b6c4edebf76d767e5a1f4d369d44b36a1683673dd6"

  strings:
    $s1 = "LBuilt using an evaluation version of {smartassembly}. Cannot be distributed." fullword ascii
    $s2 = " exile" fullword wide
    $s3 = "This assembly has been built with an evaluation version of {smartassembly}, which has expired." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}