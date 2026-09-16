rule sig_20160823_5854b844bdfed1d971dd94c38819527b {
  meta:
    description = "datamaliciousorder - file 20160823_5854b844bdfed1d971dd94c38819527b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abe8a60febf98d4433612ef2548ee85bf561e371b2a7bd5eb969b310658f0ec4"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}