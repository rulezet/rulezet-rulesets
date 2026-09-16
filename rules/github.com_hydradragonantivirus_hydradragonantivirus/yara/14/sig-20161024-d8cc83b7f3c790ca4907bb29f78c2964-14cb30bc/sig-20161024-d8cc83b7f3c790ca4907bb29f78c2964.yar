rule sig_20161024_d8cc83b7f3c790ca4907bb29f78c2964 {
  meta:
    description = "datamaliciousorder - file 20161024_d8cc83b7f3c790ca4907bb29f78c2964.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2bc64c1eb0f891341f0cc6fe5d9ecefcca8a2f0af126b5eb66b5245b3b3761c"

  strings:
    $s1 = "} while (hc++ < gd);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}