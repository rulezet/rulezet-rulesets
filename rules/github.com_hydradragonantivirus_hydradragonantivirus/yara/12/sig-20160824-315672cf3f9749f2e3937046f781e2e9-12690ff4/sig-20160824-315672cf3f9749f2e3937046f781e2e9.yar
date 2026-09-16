rule sig_20160824_315672cf3f9749f2e3937046f781e2e9 {
  meta:
    description = "datamaliciousorder - file 20160824_315672cf3f9749f2e3937046f781e2e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "418e1d8c0601c7794d2c2858534880db2550f1c5be755e1884b7126597787ecd"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}