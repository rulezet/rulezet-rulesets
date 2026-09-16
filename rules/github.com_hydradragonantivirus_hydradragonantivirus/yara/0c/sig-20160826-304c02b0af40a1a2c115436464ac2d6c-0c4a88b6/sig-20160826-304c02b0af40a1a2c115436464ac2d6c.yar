rule sig_20160826_304c02b0af40a1a2c115436464ac2d6c {
  meta:
    description = "datamaliciousorder - file 20160826_304c02b0af40a1a2c115436464ac2d6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98ee033b7a13b87ddfd780365dca770d1a787e671fc8b373a583507c9f725e57"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"\\x6a\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}