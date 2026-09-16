rule sig_20161024_6d0533ab2f322b6b352bc74137982127 {
  meta:
    description = "datamaliciousorder - file 20161024_6d0533ab2f322b6b352bc74137982127.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e81644da70eb4ead8b83f16533b987d2ccff2aaea64eb7d255bf47fa7f8f1d91"

  strings:
    $s1 = "} while (xt++ < an0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}