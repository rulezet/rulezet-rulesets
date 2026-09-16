rule sig_20160823_0d967746e57a8ceedfbdb5fcd0fde2f8 {
  meta:
    description = "datamaliciousorder - file 20160823_0d967746e57a8ceedfbdb5fcd0fde2f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81db89912dae153b7c669051e031c11ce89ee7ad9e1d433c81a8657d00174f52"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}