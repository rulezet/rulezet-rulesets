rule sig_20161024_a6ae0f6c84d18bf404826d6668eea007 {
  meta:
    description = "datamaliciousorder - file 20161024_a6ae0f6c84d18bf404826d6668eea007.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fcffb37ae627d20713a41057e69d511782a9bc648f20b80854a3ff138a31d97"

  strings:
    $s1 = "} while (qn++ < og);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}