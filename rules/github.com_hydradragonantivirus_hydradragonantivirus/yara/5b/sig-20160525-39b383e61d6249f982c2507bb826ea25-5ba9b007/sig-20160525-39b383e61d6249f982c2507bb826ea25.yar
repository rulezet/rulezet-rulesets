rule sig_20160525_39b383e61d6249f982c2507bb826ea25 {
  meta:
    description = "datamaliciousorder - file 20160525_39b383e61d6249f982c2507bb826ea25.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af5ef39cd64c25f295f418e06c90ab8ed9145e98e80511f6dc639a1e237334e6"

  strings:
    $s1 = "loca rav" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}