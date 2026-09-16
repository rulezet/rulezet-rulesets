rule sig_20160826_401d3973747d3ad3a96d899dd25feabb {
  meta:
    description = "datamaliciousorder - file 20160826_401d3973747d3ad3a96d899dd25feabb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f9a025b926911093ad9e9701fdc7b8e064aaec7786cc030d8fd84e266d3fe34"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"\\x6a\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}