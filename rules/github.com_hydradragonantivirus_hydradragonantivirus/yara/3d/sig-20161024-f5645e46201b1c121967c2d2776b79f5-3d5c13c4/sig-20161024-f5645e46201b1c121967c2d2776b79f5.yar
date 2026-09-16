rule sig_20161024_f5645e46201b1c121967c2d2776b79f5 {
  meta:
    description = "datamaliciousorder - file 20161024_f5645e46201b1c121967c2d2776b79f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eed0dff120f999aa0d46f501ff46bcaec7e9adc466d0a34f9b2a95f9de500410"

  strings:
    $s1 = "} while (yh1++ < kk);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}