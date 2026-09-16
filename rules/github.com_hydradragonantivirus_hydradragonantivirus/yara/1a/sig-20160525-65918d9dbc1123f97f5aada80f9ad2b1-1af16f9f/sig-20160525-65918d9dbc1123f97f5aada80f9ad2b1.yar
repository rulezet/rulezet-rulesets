rule sig_20160525_65918d9dbc1123f97f5aada80f9ad2b1 {
  meta:
    description = "datamaliciousorder - file 20160525_65918d9dbc1123f97f5aada80f9ad2b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ef16e7505b71d2249d176f890fd4e302d2421ee1e4599d9cf2f2fe84d0610c2"

  strings:
    $s1 = "dark rav\\n;\"e6x\\\\e\" = keppelk rav;};ssorcak nruter{)ssorcak(sdnetk noitcnuf;};deerdk nruter{)deerdk(modnark noitcnuf\\n;\"4" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}