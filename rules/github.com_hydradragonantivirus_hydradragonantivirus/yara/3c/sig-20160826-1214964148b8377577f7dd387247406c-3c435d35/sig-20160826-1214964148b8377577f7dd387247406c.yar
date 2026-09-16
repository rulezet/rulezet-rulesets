rule sig_20160826_1214964148b8377577f7dd387247406c {
  meta:
    description = "datamaliciousorder - file 20160826_1214964148b8377577f7dd387247406c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "661efa9fee31a022d3935d44bad79a730064b63c0104ba92204438c59213e37b"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"\\x6a\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}