rule sig_20160826_c732186c2b3261641cca8f97b68f647b {
  meta:
    description = "datamaliciousorder - file 20160826_c732186c2b3261641cca8f97b68f647b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa98680433b10cd818838bdf458dc8c7ac8b13eb71463a1928ac672f9883dc07"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4d\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x65\",\"\\x2b" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}