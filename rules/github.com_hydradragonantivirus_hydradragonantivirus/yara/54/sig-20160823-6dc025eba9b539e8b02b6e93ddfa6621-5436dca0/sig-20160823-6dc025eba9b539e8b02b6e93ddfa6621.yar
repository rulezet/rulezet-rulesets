rule sig_20160823_6dc025eba9b539e8b02b6e93ddfa6621 {
  meta:
    description = "datamaliciousorder - file 20160823_6dc025eba9b539e8b02b6e93ddfa6621.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ea41f3e603983440bbbe253b4edfe76e77088b63c12f66b49c9d4e8fd992a2b"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}