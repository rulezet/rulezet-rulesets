rule sig_20161024_370d8935e1af465959938765bb66a3ac {
  meta:
    description = "datamaliciousorder - file 20161024_370d8935e1af465959938765bb66a3ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8905bed7a2232406381fd3d622b02652abd0644c8ac2636b8e9c88fc7de70dd2"

  strings:
    $s1 = "} while (xi++ < yr);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}