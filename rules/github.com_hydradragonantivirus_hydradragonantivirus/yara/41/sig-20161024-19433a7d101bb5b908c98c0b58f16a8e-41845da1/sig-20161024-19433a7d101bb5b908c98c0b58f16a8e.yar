rule sig_20161024_19433a7d101bb5b908c98c0b58f16a8e {
  meta:
    description = "datamaliciousorder - file 20161024_19433a7d101bb5b908c98c0b58f16a8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d15b1e96791c1790a7cb86c4f3c48b01f5acdc80420f1c4352fed39180a91b7"

  strings:
    $s1 = "} while (eg++ < zm);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}