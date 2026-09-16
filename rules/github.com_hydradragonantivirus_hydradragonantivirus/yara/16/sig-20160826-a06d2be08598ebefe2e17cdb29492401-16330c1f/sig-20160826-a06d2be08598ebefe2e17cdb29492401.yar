rule sig_20160826_a06d2be08598ebefe2e17cdb29492401 {
  meta:
    description = "datamaliciousorder - file 20160826_a06d2be08598ebefe2e17cdb29492401.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c27683d6028d38f5bf0b5671329b438650a82756895146e80d8e74937ad1941"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x44\",\"\\x49\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x6f" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}