rule sig_20161024_d217974af84c625910fd9a79b79fc2d3 {
  meta:
    description = "datamaliciousorder - file 20161024_d217974af84c625910fd9a79b79fc2d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd8d42d2f2fb8945d991056dbc2fce5fb7e63f0914531f78a2235dbbea81b489"

  strings:
    $s1 = "} while (jw++ < yj);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}