rule sig_20160826_695f78ae3a46d13a4dffc73d281b7faa {
  meta:
    description = "datamaliciousorder - file 20160826_695f78ae3a46d13a4dffc73d281b7faa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d61119db307d581f516e7993cf1c0dd46c2bb8365928a2a049614d5a11eaca4"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4d\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x65\",\"\\x2b" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}