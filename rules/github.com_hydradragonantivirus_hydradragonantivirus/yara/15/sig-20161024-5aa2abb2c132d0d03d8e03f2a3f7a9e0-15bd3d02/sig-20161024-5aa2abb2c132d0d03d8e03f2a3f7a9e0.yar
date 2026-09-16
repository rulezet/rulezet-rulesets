rule sig_20161024_5aa2abb2c132d0d03d8e03f2a3f7a9e0 {
  meta:
    description = "datamaliciousorder - file 20161024_5aa2abb2c132d0d03d8e03f2a3f7a9e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97b1e7d8f3ca2b4d70a96f25626fa440713e7f4b550774d83c8fac1edc57b64b"

  strings:
    $s1 = "} while (qy++ < hj);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}