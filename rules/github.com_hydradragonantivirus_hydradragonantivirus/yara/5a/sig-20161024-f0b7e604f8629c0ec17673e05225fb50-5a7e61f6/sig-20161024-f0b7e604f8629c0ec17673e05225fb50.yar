rule sig_20161024_f0b7e604f8629c0ec17673e05225fb50 {
  meta:
    description = "datamaliciousorder - file 20161024_f0b7e604f8629c0ec17673e05225fb50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adbd1681d397d531ae1d55fda8ea1b258026b15dc07c09371a2577157c327fb2"

  strings:
    $s1 = "} while (oi0++ < ib);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}