rule sig_20161024_a4175e81441365fd4f1db3ba7a3b0f98 {
  meta:
    description = "datamaliciousorder - file 20161024_a4175e81441365fd4f1db3ba7a3b0f98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab398481217c96f4531b79102ae29c85b823a5227d30eca56dc9a9fd3e4eb623"

  strings:
    $s1 = "} while (vv++ < ou);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}