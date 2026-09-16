rule sig_20161024_a17b2b67a59aad5393610a97208507c5 {
  meta:
    description = "datamaliciousorder - file 20161024_a17b2b67a59aad5393610a97208507c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "196f44370769666da8dbb419ba066e55fcead0f9dab82c7b1b84c1e5c898dda3"

  strings:
    $s1 = "} while (ip++ < op);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}