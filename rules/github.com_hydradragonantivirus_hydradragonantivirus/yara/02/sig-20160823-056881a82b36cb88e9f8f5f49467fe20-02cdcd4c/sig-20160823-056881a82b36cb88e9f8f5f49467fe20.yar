rule sig_20160823_056881a82b36cb88e9f8f5f49467fe20 {
  meta:
    description = "datamaliciousorder - file 20160823_056881a82b36cb88e9f8f5f49467fe20.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb8fe8c609632add9df1c3fa7360302d10686b3fff2709d5fc46193212b45bf8"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}