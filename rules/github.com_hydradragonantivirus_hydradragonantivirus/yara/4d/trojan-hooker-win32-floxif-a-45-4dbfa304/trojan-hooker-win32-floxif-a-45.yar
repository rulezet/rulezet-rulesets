rule Trojan_Hooker_Win32_Floxif_A_45 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_45.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcb298f87895e5fb48d3ee2faa9b0f0719cbe3425fedbf77a3f7bd8c679f73fb"

  strings:
    $s1 = "Copyright (C) 2002 - 2024" fullword wide
    $s2 = "<description>Green software</description>" fullword ascii
    $s3 = "code@Addr" fullword ascii
    $s4 = "peri$MZ" fullword ascii
    $s5 = "tige@s" fullword ascii
    $s6 = "!QrdW=UzObo" fullword ascii
    $s7 = "qc7onDisable " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}