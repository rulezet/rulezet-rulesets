rule sig_20160822_b77f41e4dbd7e654a3b6e1d4eea93dcc {
  meta:
    description = "datamaliciousorder - file 20160822_b77f41e4dbd7e654a3b6e1d4eea93dcc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dc96a64e5cfe9e52dbd8987900a24ebb08338e4405a07e85c2c02d092c7a994"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}