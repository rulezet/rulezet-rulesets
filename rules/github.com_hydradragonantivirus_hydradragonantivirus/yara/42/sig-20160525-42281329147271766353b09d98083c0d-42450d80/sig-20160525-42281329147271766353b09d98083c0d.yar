rule sig_20160525_42281329147271766353b09d98083c0d {
  meta:
    description = "datamaliciousorder - file 20160525_42281329147271766353b09d98083c0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3ea1eb06d470005fc15cf480ba9b7f7eb14fa410e5974e4b67d969f5fe87c02"

  strings:
    $s1 = "dark rav\\n;\"e6x\\\\e\" = keppelk rav;};ssorcak nruter{)ssorcak(sdnetk noitcnuf;};deerdk nruter{)deerdk(modnark noitcnuf\\n;\"4" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}