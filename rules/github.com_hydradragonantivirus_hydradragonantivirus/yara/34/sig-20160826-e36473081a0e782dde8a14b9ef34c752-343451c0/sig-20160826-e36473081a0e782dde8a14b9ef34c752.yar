rule sig_20160826_e36473081a0e782dde8a14b9ef34c752 {
  meta:
    description = "datamaliciousorder - file 20160826_e36473081a0e782dde8a14b9ef34c752.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d8d3c76b8f0e2423bd776f42cb93eb796f9b36f726ea109b1b7cb543db11874"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4d\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x65\",\"\\x2b" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}