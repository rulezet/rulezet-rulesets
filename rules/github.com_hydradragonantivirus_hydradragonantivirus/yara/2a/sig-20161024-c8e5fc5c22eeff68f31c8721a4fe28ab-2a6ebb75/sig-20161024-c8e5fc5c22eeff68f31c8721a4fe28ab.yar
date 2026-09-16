rule sig_20161024_c8e5fc5c22eeff68f31c8721a4fe28ab {
  meta:
    description = "datamaliciousorder - file 20161024_c8e5fc5c22eeff68f31c8721a4fe28ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5a64c4a5f56e0aeff7bb878b18eda0a3f1160c69925af0ebea995201ca21d7b"

  strings:
    $s1 = "} while (en++ < ww);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}