rule sig_20161024_d672f1138386bf1d8df1057ea8ac0182 {
  meta:
    description = "datamaliciousorder - file 20161024_d672f1138386bf1d8df1057ea8ac0182.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "101f7539c97452bfacd75c642d07abb0bcee8285ff13b7c9e1014662b13da54c"

  strings:
    $s1 = "} while (bx0++ < gi);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}