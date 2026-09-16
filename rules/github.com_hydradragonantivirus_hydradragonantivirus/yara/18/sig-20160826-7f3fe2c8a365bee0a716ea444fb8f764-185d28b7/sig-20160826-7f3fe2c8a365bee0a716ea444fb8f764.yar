rule sig_20160826_7f3fe2c8a365bee0a716ea444fb8f764 {
  meta:
    description = "datamaliciousorder - file 20160826_7f3fe2c8a365bee0a716ea444fb8f764.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86ce2469e8aeaec7a7ce9dd62ddf0566a630bfc2397a4ad1896f2a63bab713b8"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x46\",\"\\x64\",\"0\",\"\\x3d\",\"\\x22\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}