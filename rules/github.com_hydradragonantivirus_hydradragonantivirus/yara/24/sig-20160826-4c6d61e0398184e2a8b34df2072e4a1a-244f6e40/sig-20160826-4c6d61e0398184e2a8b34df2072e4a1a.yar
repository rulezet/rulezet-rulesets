rule sig_20160826_4c6d61e0398184e2a8b34df2072e4a1a {
  meta:
    description = "datamaliciousorder - file 20160826_4c6d61e0398184e2a8b34df2072e4a1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be1a95350b52d254fe86b1199f32c7bb4ab21adce5fef53e271e309d07b19591"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"\\x6a\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}