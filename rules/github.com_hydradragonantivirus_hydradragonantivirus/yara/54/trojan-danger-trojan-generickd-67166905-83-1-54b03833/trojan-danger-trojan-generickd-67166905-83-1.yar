rule Trojan_Danger_Trojan_GenericKD_67166905_83_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_83_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4c665202d7f90bbc6ba43dab58a7a785dbd56f7b71c247bb30164536e0038f9"

  strings:
    $s1 = "@8dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}