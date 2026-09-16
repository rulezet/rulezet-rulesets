rule sig_20161024_71dc7603abe030a3f46f8ecf7f3987b8 {
  meta:
    description = "datamaliciousorder - file 20161024_71dc7603abe030a3f46f8ecf7f3987b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcbefa754febab2f181eab6994313c69ca0162d37afff062719700e3f9441d96"

  strings:
    $s1 = "} while (xz++ < xb);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}