rule sig_20161024_32842b4ccc65360e4a39dd9b0dcf3385 {
  meta:
    description = "datamaliciousorder - file 20161024_32842b4ccc65360e4a39dd9b0dcf3385.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb5d3bfe9859cb2594fe43b4934c8738d6f58ff08d29a98fb29bed07df3b783c"

  strings:
    $s1 = "} while (op++ < sy);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}