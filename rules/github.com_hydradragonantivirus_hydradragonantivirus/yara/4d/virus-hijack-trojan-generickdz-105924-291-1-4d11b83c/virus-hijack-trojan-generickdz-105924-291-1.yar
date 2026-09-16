rule Virus_Hijack_Trojan_GenericKDZ_105924_291_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_291_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08d7bfd5f3dabf3c995e604fd0204466c79e37cc0ecea40475f343f7903d7fb0"

  strings:
    $s1 = "#Biwa!" fullword ascii
    $s2 = "sAiR.}" fullword ascii
    $s3 = "C\"rEsP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}