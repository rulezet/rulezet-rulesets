rule sig_20161024_8c3d7ddace517befa171b608be75b353 {
  meta:
    description = "datamaliciousorder - file 20161024_8c3d7ddace517befa171b608be75b353.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "378d45d6d02d95cd2806b4cfe8cf925098846d5b1d042f0f816ef4bf14a2be21"

  strings:
    $s1 = "} while (hj++ < qz);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}