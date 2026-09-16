rule sig_20161024_87565a8a543e7286e795613e018764a0 {
  meta:
    description = "datamaliciousorder - file 20161024_87565a8a543e7286e795613e018764a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29c4b96777f4094baf0dfedf5b94a8debf5c23d79f227628a0a31ae831006eb3"

  strings:
    $s1 = "} while (in0++ < jo);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}