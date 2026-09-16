rule Trojan_Danger_Trojan_Agent_EMNR {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.Agent.EMNR.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bd3a641099a9ae5eafedab07ca49c817019af1c7b876d3583089a46ea8fa7bc"

  strings:
    $s1  = "&Target Frame:" fullword wide
    $s2  = "2 - Circle In" fullword wide
    $s3  = "3 - Circle Out" fullword wide
    $s4  = "for the connection, click Configure, then Advanced." fullword wide
    $s5  = "#Microsoft ISDN Configuration WizardbNo ISDN devices were found.  Please install an ISDN device and run the configuration wizard" wide
    $s6  = "0 - Uniform" fullword wide
    $s7  = "3 - Rectangular" fullword wide
    $s8  = "4 - Wipe Up" fullword wide
    $s9  = "5 - Wipe Down" fullword wide
    $s10 = "6 - Wipe Right" fullword wide
    $s11 = "7 - Wipe Left" fullword wide
    $s12 = "9 - Horizontal Blinds" fullword wide
    $s13 = "10 - Checkerboard Across" fullword wide
    $s14 = "11 - Checkerboard Down" fullword wide
    $s15 = "12 - Random Dissolve" fullword wide
    $s16 = "15 - Split Horizontal In" fullword wide
    $s17 = "16 - Split Horizontal Out" fullword wide
    $s18 = "17 - Strips Left Down" fullword wide
    $s19 = "18 - Strips Left Up" fullword wide
    $s20 = "19 - Strips Right Down" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}