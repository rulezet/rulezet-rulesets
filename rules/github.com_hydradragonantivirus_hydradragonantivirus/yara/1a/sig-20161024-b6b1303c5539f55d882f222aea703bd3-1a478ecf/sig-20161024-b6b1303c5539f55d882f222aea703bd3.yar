rule sig_20161024_b6b1303c5539f55d882f222aea703bd3 {
  meta:
    description = "datamaliciousorder - file 20161024_b6b1303c5539f55d882f222aea703bd3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfcf42c0ee6e9c6824ff550c135856d0df9358ffa4ad0d8edf940df55958e52b"

  strings:
    $s1 = "} while (vi0++ < ng0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}