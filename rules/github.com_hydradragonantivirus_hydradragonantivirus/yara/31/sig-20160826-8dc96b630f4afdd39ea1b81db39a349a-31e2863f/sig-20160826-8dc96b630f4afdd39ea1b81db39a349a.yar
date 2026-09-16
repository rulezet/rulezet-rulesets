rule sig_20160826_8dc96b630f4afdd39ea1b81db39a349a {
  meta:
    description = "datamaliciousorder - file 20160826_8dc96b630f4afdd39ea1b81db39a349a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "982030117d413408d08348399ba760db7529b395a2b5856118a83a1a6b79d55f"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x44\",\"\\x49\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x6f" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}