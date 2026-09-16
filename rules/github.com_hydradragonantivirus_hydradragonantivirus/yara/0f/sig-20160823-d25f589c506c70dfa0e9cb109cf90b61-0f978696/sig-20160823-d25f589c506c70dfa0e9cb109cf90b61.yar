rule sig_20160823_d25f589c506c70dfa0e9cb109cf90b61 {
  meta:
    description = "datamaliciousorder - file 20160823_d25f589c506c70dfa0e9cb109cf90b61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d0c4ccb26d4f0aa2cffd42dfe6185d203733e6e3b0a125c502a304fde8ee743"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}