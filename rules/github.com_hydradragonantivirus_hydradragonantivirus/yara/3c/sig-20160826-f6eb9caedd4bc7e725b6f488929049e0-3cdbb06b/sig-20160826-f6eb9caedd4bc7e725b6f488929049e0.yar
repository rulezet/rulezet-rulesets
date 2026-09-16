rule sig_20160826_f6eb9caedd4bc7e725b6f488929049e0 {
  meta:
    description = "datamaliciousorder - file 20160826_f6eb9caedd4bc7e725b6f488929049e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7987d241b4878586e14d9abfd145c7c05d03524169cfdff3013603800cfb7b7"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"\\x6a\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}