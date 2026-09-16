rule sig_20160826_92f7b550de4ac5a58d32df78305be789 {
  meta:
    description = "datamaliciousorder - file 20160826_92f7b550de4ac5a58d32df78305be789.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4895aceba4ba43db648fa2b8c025db4be754d896974acfcbd9cf3f218046779"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x46\",\"\\x57\",\"0\",\"\\x3d\",\"\\x22\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}