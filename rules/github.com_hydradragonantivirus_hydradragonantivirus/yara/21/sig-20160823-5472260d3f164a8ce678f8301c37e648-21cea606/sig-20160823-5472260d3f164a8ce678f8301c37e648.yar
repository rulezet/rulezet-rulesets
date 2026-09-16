rule sig_20160823_5472260d3f164a8ce678f8301c37e648 {
  meta:
    description = "datamaliciousorder - file 20160823_5472260d3f164a8ce678f8301c37e648.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f849927f6484b94b96c9dbb7077a630e0d928ff0b78f64b15b334427256defa"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}