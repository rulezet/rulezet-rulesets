rule sig_20160826_12fbe9f903005efb984ff117a90f0592 {
  meta:
    description = "datamaliciousorder - file 20160826_12fbe9f903005efb984ff117a90f0592.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38c50b0e789b329a835dca04da648e35b89946970110828bf8ca0b23b6886759"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x46\",\"\\x57\",\"0\",\"\\x3d\",\"\\x22\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}