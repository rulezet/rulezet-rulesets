rule sig_20160823_c4c1d2a4a8c8e4af6311609851bae594 {
  meta:
    description = "datamaliciousorder - file 20160823_c4c1d2a4a8c8e4af6311609851bae594.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04e9c71ae222f9debccd353a6624f1e6fb9f258eb28c8482f82082510ef6f094"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}