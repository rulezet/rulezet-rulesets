rule sig_20160826_54780da18c7b71e1b0177fd9e04228fa {
  meta:
    description = "datamaliciousorder - file 20160826_54780da18c7b71e1b0177fd9e04228fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0fd2d8bf2d6f7de6bbdd9d894be52d46b578bd34f41ed2d0f98a1e2bfb1f813"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4b\",\"\\x6e\",\"\\x3d\",\"\\x22\",\"\\x63\",\"\\x6c" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}