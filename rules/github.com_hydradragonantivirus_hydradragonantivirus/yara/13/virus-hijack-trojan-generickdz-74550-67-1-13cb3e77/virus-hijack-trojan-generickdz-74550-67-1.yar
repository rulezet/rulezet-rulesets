rule Virus_Hijack_Trojan_GenericKDZ_74550_67_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_67_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ac5b3a3ca4bbc8e47e0ac85179445944b6d03c60bb7ca037a2c4ec45a9424f8"

  strings:
    $s1 = "\\]gLAm" fullword ascii
    $s2 = "i!{W{$LAet" fullword ascii
    $s3 = "'$WhOO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}