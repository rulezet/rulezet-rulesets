rule sig_20160823_23ad85416a9006d401dd87720afe36b5 {
  meta:
    description = "datamaliciousorder - file 20160823_23ad85416a9006d401dd87720afe36b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4488b52aa62f793d8f3d53927761cd63da017838778b8a668b38b1d7d5aed74"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}