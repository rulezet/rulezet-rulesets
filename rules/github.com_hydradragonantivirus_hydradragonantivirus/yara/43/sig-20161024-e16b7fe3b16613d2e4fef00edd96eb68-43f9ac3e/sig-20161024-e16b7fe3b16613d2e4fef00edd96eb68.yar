rule sig_20161024_e16b7fe3b16613d2e4fef00edd96eb68 {
  meta:
    description = "datamaliciousorder - file 20161024_e16b7fe3b16613d2e4fef00edd96eb68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c15b955db3a6b99915a98e962cb008d0335e5680f24bc67582b4c0a587c2cf9c"

  strings:
    $s1 = "} while (tp++ < za);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}