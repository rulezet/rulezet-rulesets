rule Virus_Sysbot_Trojan_GenericKD_71671752_19_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35e0d0f566eab2d1935ef0bb721a79415729715ecb37e24ce8a7374c0ab8d42c"

  strings:
    $s1 = "thOo])" fullword ascii
    $s2 = "bigg&B" fullword ascii
    $s3 = "X^Q#guru" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}