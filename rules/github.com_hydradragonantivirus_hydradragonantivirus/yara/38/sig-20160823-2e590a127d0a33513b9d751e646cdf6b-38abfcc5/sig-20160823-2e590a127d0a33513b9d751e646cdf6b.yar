rule sig_20160823_2e590a127d0a33513b9d751e646cdf6b {
  meta:
    description = "datamaliciousorder - file 20160823_2e590a127d0a33513b9d751e646cdf6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2368d251d7c6b45c48f75fc67845ece240c19474ec4b9b9ba5b9802092358a95"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}