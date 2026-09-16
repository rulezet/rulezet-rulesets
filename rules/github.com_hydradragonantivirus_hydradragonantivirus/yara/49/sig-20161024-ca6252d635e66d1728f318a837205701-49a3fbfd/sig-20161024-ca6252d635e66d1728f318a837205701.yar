rule sig_20161024_ca6252d635e66d1728f318a837205701 {
  meta:
    description = "datamaliciousorder - file 20161024_ca6252d635e66d1728f318a837205701.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6625662033b8aacac1721921b8ac01aa3cbeee4965d19178cb640951db3cf810"

  strings:
    $s1 = "} while (yn++ < ks);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}