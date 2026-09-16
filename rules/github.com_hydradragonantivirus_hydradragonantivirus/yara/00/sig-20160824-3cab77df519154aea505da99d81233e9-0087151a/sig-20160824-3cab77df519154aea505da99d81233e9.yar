rule sig_20160824_3cab77df519154aea505da99d81233e9 {
  meta:
    description = "datamaliciousorder - file 20160824_3cab77df519154aea505da99d81233e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd04aa41031324748497bea8f2f577ffbfef856ab6097e847ef3ca9073446bd2"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}