rule sig_20160826_1d26a6adb0d9abb1d9eaf155f122b3e0 {
  meta:
    description = "datamaliciousorder - file 20160826_1d26a6adb0d9abb1d9eaf155f122b3e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32475b7e210e3d1d2d110bc5e196c16f4164f72437fa904f17c85738ac53b40c"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4d\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x65\",\"\\x2b" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}