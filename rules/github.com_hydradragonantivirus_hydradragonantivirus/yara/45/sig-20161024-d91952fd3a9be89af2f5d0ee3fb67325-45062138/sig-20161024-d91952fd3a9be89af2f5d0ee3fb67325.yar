rule sig_20161024_d91952fd3a9be89af2f5d0ee3fb67325 {
  meta:
    description = "datamaliciousorder - file 20161024_d91952fd3a9be89af2f5d0ee3fb67325.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "755ed8838560850f835b81a61e8fb96af84f0df05e60fe142a3b5912f74da065"

  strings:
    $s1 = "} while (an++ < xq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}