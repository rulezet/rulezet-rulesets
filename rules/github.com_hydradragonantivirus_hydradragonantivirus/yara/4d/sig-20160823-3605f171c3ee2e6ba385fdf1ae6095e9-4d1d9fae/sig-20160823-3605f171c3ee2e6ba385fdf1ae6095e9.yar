rule sig_20160823_3605f171c3ee2e6ba385fdf1ae6095e9 {
  meta:
    description = "datamaliciousorder - file 20160823_3605f171c3ee2e6ba385fdf1ae6095e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecd42c4f6913c5e6bbdc3ce5d7aeaa2267308c85e81f72520131043c22231da9"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}