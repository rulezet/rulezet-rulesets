rule sig_20160826_5a2079bfd9b1dc8a91751c2b46127830 {
  meta:
    description = "datamaliciousorder - file 20160826_5a2079bfd9b1dc8a91751c2b46127830.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f34b63716b35f65df8443135efca3e564664292170918bc70a5383f424a8300"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"\\x6a\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}