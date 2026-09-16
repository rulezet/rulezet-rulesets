rule sig_20160823_3fd94c298f52049dce7b27b533fa104b {
  meta:
    description = "datamaliciousorder - file 20160823_3fd94c298f52049dce7b27b533fa104b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4b06c66707b536070d9d561e452c50529aad001b7e5b0fade9c7ca6a01ed0eb"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}