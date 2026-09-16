rule Virus_Hijack_Trojan_GenericKDZ_74550_86_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_86_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92f107e7b85a8003dea4ab7f353e14bfb3893591c148fe87a08c7575eaa9eec2"

  strings:
    $s1 = "1?TOro" fullword ascii
    $s2 = "7&DAlE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}