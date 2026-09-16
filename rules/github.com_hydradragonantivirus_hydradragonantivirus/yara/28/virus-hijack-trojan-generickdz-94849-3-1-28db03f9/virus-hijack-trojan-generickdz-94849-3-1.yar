rule Virus_Hijack_Trojan_GenericKDZ_94849_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30de752731985c9052234b80f5887917c8751f4375e2ad37148326a3e420da6b"

  strings:
    $s1 = "??RINk" fullword ascii
    $s2 = "d%eNSe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}