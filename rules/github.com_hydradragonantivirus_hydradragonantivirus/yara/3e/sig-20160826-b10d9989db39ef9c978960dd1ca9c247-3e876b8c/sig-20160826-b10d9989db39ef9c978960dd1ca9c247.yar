rule sig_20160826_b10d9989db39ef9c978960dd1ca9c247 {
  meta:
    description = "datamaliciousorder - file 20160826_b10d9989db39ef9c978960dd1ca9c247.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddc731952bf9a0431227d968cc66a161674006f7146cce5e6716c071f8ce3ddc"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"\\x6a\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}