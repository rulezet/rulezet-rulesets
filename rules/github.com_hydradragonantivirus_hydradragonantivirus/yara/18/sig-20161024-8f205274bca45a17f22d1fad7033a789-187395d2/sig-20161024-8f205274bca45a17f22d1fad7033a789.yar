rule sig_20161024_8f205274bca45a17f22d1fad7033a789 {
  meta:
    description = "datamaliciousorder - file 20161024_8f205274bca45a17f22d1fad7033a789.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c0efcc211df698123d375e63d24195bcc2eba9d686b5350d8a09b161c269676"

  strings:
    $s1 = "} while (gh0++ < xo);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}