rule sig_20161024_cc675c455ae8324e141f947bb33e1e90 {
  meta:
    description = "datamaliciousorder - file 20161024_cc675c455ae8324e141f947bb33e1e90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de95f0041a97fd12b8effc4ccf3ca8eae6286c6f98f7ff186dd7ef73a4eb1bcc"

  strings:
    $s1 = "} while (ac++ < qb);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}