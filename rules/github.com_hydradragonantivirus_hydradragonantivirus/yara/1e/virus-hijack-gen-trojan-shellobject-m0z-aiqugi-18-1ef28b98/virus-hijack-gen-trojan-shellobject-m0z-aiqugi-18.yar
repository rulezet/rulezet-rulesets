rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1fe3e4522b701047d35e034db5ed2e9b8b10619b15f3d1a0b44b8da1a499352"

  strings:
    $s1  = "Not a base32 string" fullword wide
    $s2  = "$STATIC$InitBitmap$2001$lastW" fullword ascii
    $s3  = "Telegram Desktop" fullword ascii
    $s4  = "Copyright (C) 2014-2021" fullword wide
    $s5  = "Telegram FZ-LLC" fullword ascii
    $s6  = "$STATIC$InitBitmap$2001$lastW$Init" fullword ascii
    $s7  = "$STATIC$InitBitmap$2001$lastH" fullword ascii
    $s8  = "$STATIC$InitBitmap$2001$lastH$Init" fullword ascii
    $s9  = "Barnsley fern" fullword wide
    $s10 = "Pack Ferret" fullword wide
    $s11 = "Test Pack" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}