rule VirusShareTrojanDownLoader3951305 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader3951305.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd2fe7162337d7ac5dcde806f710ac01669bf66fbb28ee377dd9287d2a464bf2"

  strings:
    $s1  = "Process Killer" fullword ascii
    $s2  = "Process Hacker" fullword ascii
    $s3  = "System Explorer" fullword ascii
    $s4  = "Accept-Encoding: deflate, gzip, x-gzip, identity, *;q=0" fullword ascii
    $s5  = "This module is part of Zoner Photo Studio and other related products." fullword wide
    $s6  = "Zoner Photo Studio X" fullword wide
    $s7  = "Copyright 1997-2019" fullword wide
    $s8  = "Rich;G" fullword ascii
    $s9  = "TAUM]D" fullword ascii
    $s10 = "Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}