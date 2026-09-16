rule sig_20160826_7c954dadbd60eeecb04c841f5a38d5ad {
  meta:
    description = "datamaliciousorder - file 20160826_7c954dadbd60eeecb04c841f5a38d5ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fec43d05e22497f7e15754ef1fc60ab5b19a7dfe05e8cae10948ac92571b3b5b"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"3\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65\"," ascii
    $s2 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"3\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}