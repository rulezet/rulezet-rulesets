rule sig_20160822_79da6c7f9e29d4a649b3be321a70a529 {
  meta:
    description = "datamaliciousorder - file 20160822_79da6c7f9e29d4a649b3be321a70a529.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c749cec6c97381ac010c7e19e91a0f6fe51ecde25d4678d0288ec0b02109b4d8"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}