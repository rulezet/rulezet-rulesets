rule Virus_Hijack_Trojan_GenericKDZ_98388_91_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_91_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7dbd6a0d656ec1f250fbd1a43a4d41b2cd25ab96af303765d1051cc5d796042"

  strings:
    $s1 = "AKEy>B" fullword ascii
    $s2 = "WW>wEAR" fullword ascii
    $s3 = "SS&}wonE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}