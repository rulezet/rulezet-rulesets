rule sig_20161024_a8a0e6ecc8c2d10f61d8d7f8ad9a0057 {
  meta:
    description = "datamaliciousorder - file 20161024_a8a0e6ecc8c2d10f61d8d7f8ad9a0057.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "270c35d44d8a5da625990e989a5a76521c6d96a5343d6cf291861300701127de"

  strings:
    $s1 = "} while (eb0++ < ba0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}