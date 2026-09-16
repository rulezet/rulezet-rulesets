rule sig_20160823_b54f7ea22e52d3d66bca79890c049556 {
  meta:
    description = "datamaliciousorder - file 20160823_b54f7ea22e52d3d66bca79890c049556.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b3f94ed7e4777e525112a5f5b48ba139e1daec5d8bc48b35b06e936a3530f0e"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}