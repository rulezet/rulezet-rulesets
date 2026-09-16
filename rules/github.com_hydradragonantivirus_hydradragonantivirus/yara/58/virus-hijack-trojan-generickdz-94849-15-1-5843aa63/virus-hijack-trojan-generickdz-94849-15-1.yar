rule Virus_Hijack_Trojan_GenericKDZ_94849_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfb771c7c9d281dca0e4511fe16d9f2c92993f00492988f060577daabdb3c253"

  strings:
    $s1 = "JoLL@pBG9" fullword ascii
    $s2 = "\"]KiSt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}