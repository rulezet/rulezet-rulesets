rule sig_20161024_c6ba86e9e7c7a5e13c516378a5764307 {
  meta:
    description = "datamaliciousorder - file 20161024_c6ba86e9e7c7a5e13c516378a5764307.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6241c8f354130c5dcf65402a1b00a34a7597b4a8a36d334fd7d5f8c9e3ba38f4"

  strings:
    $s1 = "} while (jp++ < sb);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}