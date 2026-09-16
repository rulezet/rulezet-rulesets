rule sig_20160823_2d6d29fc7eac567b11bf8158e3a90448 {
  meta:
    description = "datamaliciousorder - file 20160823_2d6d29fc7eac567b11bf8158e3a90448.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9da4e8124e3100234318ca35394fc4ab79c76eaef122801e65f5695c28836d83"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}