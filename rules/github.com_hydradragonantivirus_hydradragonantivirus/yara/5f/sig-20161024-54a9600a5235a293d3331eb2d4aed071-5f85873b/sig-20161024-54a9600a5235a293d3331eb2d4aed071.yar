rule sig_20161024_54a9600a5235a293d3331eb2d4aed071 {
  meta:
    description = "datamaliciousorder - file 20161024_54a9600a5235a293d3331eb2d4aed071.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ba9bc92fcd5439669ad862fe80da173e8bdc969b1d3335d5de144f283da2830"

  strings:
    $s1 = "} while (vn++ < xq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}