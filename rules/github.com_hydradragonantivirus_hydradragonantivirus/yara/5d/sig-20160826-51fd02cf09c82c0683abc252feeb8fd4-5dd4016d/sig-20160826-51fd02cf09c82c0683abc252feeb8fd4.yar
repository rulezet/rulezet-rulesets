rule sig_20160826_51fd02cf09c82c0683abc252feeb8fd4 {
  meta:
    description = "datamaliciousorder - file 20160826_51fd02cf09c82c0683abc252feeb8fd4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa051bd9fa86d720425d38c59f70f8ddfb1a5f1a912beae51b4c2707c4d433bd"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4b\",\"\\x6e\",\"\\x3d\",\"\\x22\",\"\\x63\",\"\\x6c" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}