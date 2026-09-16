rule Virus_Hijack_Trojan_GenericKDZ_98388_155_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_155_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87a81543c724bc6de0970d15487c341ac783302e91816e7d03bed9343ce31fc7"

  strings:
    $s1 = "InrO?I" fullword ascii
    $s2 = ">NEumA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}