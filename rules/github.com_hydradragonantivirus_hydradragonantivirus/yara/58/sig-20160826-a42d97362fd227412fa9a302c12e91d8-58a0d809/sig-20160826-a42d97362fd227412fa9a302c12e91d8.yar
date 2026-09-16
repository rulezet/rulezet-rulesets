rule sig_20160826_a42d97362fd227412fa9a302c12e91d8 {
  meta:
    description = "datamaliciousorder - file 20160826_a42d97362fd227412fa9a302c12e91d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bf648522b25bf3ba0ad93973d850f2691c431316ddd01d40c7e28b52d3f5732"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4d\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x65\",\"\\x2b" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}