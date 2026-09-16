rule sig_20160823_002d7db74531caae9973e6bf7c8c6563 {
  meta:
    description = "datamaliciousorder - file 20160823_002d7db74531caae9973e6bf7c8c6563.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85b4fc6782eb31f0dccc913d1f13632bad1d9599237244dd8a9cc2e22b5221b9"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}