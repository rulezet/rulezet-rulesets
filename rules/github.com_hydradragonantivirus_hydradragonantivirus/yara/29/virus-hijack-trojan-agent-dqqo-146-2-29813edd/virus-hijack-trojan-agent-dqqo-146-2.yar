rule Virus_Hijack_Trojan_Agent_DQQO_146_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_146_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3bf8f0c39dc125ae21b45dfb431087be699744ceac6986950c4309bedd4953f"

  strings:
    $x1  = "This \"Portable Network Graphics\" image is not supported because either it's width or height exceeds the maximum size, which is" wide
    $s2  = "=This control requires version 4.70 or greater of COMCTL32.DLL" fullword wide
    $s3  = "<!-- Copyright (c) Linasoft -->" fullword ascii
    $s4  = "http://www.linasoft.com for more information." fullword wide
    $s5  = "Unable to load audiere.dll, music player control may not work." fullword wide
    $s6  = "Out of memory..Unable to find any supported image file in %s.1Press ESC to quit, double click for next picture.6Press ESC to qui" wide
    $s7  = "AutoPlay Menu Loader" fullword wide
    $s8  = "Forward transformation is not implemented in %s." fullword ascii
    $s9  = "Using The Great Audio Library - Audiere" fullword wide
    $s10 = "&Enter Password:" fullword wide
    $s11 = "Plain text (*.txt)|*.txt" fullword wide
    $s12 = "<description>AutoPlay Menu Builder</description>" fullword ascii
    $s13 = "CompuServe GIF Image" fullword wide
    $s14 = "Circular reveal to centre" fullword ascii
    $s15 = "Circular reveal from centre" fullword ascii
    $s16 = "Diagonal sweep from top left bottom right clockwise" fullword ascii
    $s17 = "Sweep clockwise" fullword ascii
    $s18 = "Diagonal sweep from top left bottom right anticlockwise" fullword ascii
    $s19 = "Sweep anticlockwise" fullword ascii
    $s20 = "128-Byte PrefetchingjThis \"Portable Network Graphics\" image is not valid because it contains invalid pieces of data (crc error" wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}