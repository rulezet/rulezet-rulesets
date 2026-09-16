rule Virus_Hijack_Trojan_GenericKDZ_98388_106_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_106_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12220f2ccd91f318c21cdf4947b41bafea26a48bc80cfdf7e14e93aedd773a6c"

  strings:
    $s1 = "M!;CyaN(:CL" fullword ascii
    $s2 = ";BRee$<Ex" fullword ascii
    $s3 = "|`hISN" fullword ascii
    $s4 = "|}Yond" fullword ascii
    $s5 = "``gaWn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}