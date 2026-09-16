rule sig_20161024_f29e70958b79bdf4cb6f9e928e27c2bd {
  meta:
    description = "datamaliciousorder - file 20161024_f29e70958b79bdf4cb6f9e928e27c2bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca2eeb2be4a202edf56b03f53b42948a7edf89907ce1b0c012143ddc2644790c"

  strings:
    $s1 = "} while (cf++ < ww);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}