rule sig_20161024_a6d7049896005ebd1141c87feac397e9 {
  meta:
    description = "datamaliciousorder - file 20161024_a6d7049896005ebd1141c87feac397e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed89212c149363ff0252b68fa73ef5049c84f1cfdec79c83c23735943cd9a956"

  strings:
    $s1 = "} while (vi++ < bu);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}