rule sig_20161024_8798bed0120f8beed2ba66efb4fa4860 {
  meta:
    description = "datamaliciousorder - file 20161024_8798bed0120f8beed2ba66efb4fa4860.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5a2ef4ffe30762bd2960126345b6d6c98b8077f46af811fdea899ffbd81f34c"

  strings:
    $s1 = "} while (ov++ < mr);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}