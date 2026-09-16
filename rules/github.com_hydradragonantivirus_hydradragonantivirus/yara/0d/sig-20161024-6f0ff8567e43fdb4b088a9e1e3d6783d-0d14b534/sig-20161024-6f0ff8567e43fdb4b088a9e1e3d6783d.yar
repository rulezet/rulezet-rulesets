rule sig_20161024_6f0ff8567e43fdb4b088a9e1e3d6783d {
  meta:
    description = "datamaliciousorder - file 20161024_6f0ff8567e43fdb4b088a9e1e3d6783d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb3644336c25f312ae6d22ec7d0c10ac1329c804b7545629b859629c69b5da5a"

  strings:
    $s1 = "} while (qx++ < sf);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}