rule Worm_Gen_Variant_Downloader_126_1_1 {
  meta:
    description = "datamaliciousorder - file Worm_Gen.Variant.Downloader.126_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f109641f6f41da5c45c814ce7313f93006be9093eea022d8a8221b9ab4732de4"

  strings:
    $s1  = "VALUE \"FileVersion\", \"12.1.3.0\"" fullword ascii
    $s2  = "VALUE \"FileDescription\", \"Markel Corporation\"" fullword ascii
    $s3  = "VALUE \"ProductVersion\", \"12.1.3.0\"" fullword ascii
    $s4  = "VALUE \"OriginalFilename\", \"MarkelCorporation.exe\"" fullword ascii
    $s5  = "VALUE \"InternalName\", \"MarkelCorporation.exe\"" fullword ascii
    $s6  = "VALUE \"CompanyName\", \"Markel Corporation\"" fullword ascii
    $s7  = "VALUE \"Comments\", \"Markel Corporation Poer\"" fullword ascii
    $s8  = "VALUE \"Assembly Version\", \"9.19.15.13\"" fullword ascii
    $s9  = "Markel Corporation Poer" fullword ascii
    $s10 = "(c) 2017 Markel Corporation" fullword ascii
    $s11 = "VALUE \"LegalCopyright\", \"(c) 2017 Markel Corporation\"" fullword ascii
    $s12 = "Markel Corporation" fullword ascii
    $s13 = "VALUE \"ProductName\", \"Markel Corporation Poer\"" fullword ascii
    $s14 = "BLOCK \"000004b0\"" fullword ascii
    $s15 = "VALUE \"Translation\", 0x0000 0x04B0  " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}