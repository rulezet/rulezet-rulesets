rule sig_20160526_d9e0d95430e8a6b21775df1e608d30e6 {
  meta:
    description = "datamaliciousorder - file 20160526_d9e0d95430e8a6b21775df1e608d30e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d531b5ed1da111ba230397c90d15424b2040af104b094b8f2f6eabb7f0351e89"

  strings:
    $s1 = "F rav\\n\\r;\"gn\" = gJJTRCE rav\\n\\r;\"ht\" = wLEE rav\\n\\r;\"el\" = uWKH rav\\n\\r;\"htgn\" = 3fOUQOLA rav\\n\\r;\"nuR\" = p" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}