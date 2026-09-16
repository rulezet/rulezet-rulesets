rule sig_20161024_6d84869d8dc8a1b5072747c203f2897d {
  meta:
    description = "datamaliciousorder - file 20161024_6d84869d8dc8a1b5072747c203f2897d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02635cf0cb08ab45694ff546cdc784e6e44bc982461b9e27df41dd604de4960d"

  strings:
    $s1 = "} while (au++ < ey);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}