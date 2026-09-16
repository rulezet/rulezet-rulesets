rule sig_20161024_a05fa57629460189bbde82402b0961b0 {
  meta:
    description = "datamaliciousorder - file 20161024_a05fa57629460189bbde82402b0961b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5ed564b128f9e0da32574750e330bc7e5baee74c16b5c8ff69c9edf23ca2f4b"

  strings:
    $s1 = "} while (pm++ < yu);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}