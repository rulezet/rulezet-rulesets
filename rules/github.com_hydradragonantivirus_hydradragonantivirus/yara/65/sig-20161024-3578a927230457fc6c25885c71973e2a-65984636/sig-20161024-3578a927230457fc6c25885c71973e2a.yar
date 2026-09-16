rule sig_20161024_3578a927230457fc6c25885c71973e2a {
  meta:
    description = "datamaliciousorder - file 20161024_3578a927230457fc6c25885c71973e2a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f29f95768652cc28c74b064d4759b05b984afbcea257db7161d1877f6097d6d"

  strings:
    $s1 = "} while (it++ < ud);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}