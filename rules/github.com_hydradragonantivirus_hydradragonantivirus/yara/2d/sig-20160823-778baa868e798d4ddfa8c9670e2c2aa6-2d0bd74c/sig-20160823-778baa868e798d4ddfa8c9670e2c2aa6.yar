rule sig_20160823_778baa868e798d4ddfa8c9670e2c2aa6 {
  meta:
    description = "datamaliciousorder - file 20160823_778baa868e798d4ddfa8c9670e2c2aa6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c12ee042b2510bc5914f8d18a27b5a8062adc851340373bb2abb0d8686ebf6d"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}