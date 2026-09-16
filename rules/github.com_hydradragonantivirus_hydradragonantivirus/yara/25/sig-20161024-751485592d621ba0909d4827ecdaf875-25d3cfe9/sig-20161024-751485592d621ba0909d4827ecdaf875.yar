rule sig_20161024_751485592d621ba0909d4827ecdaf875 {
  meta:
    description = "datamaliciousorder - file 20161024_751485592d621ba0909d4827ecdaf875.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d59524802a83bf6fe1fffd10461fdc7b2e0b2e28969afef7006f45eb4e38c028"

  strings:
    $s1 = "} while (xo++ < zc);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}