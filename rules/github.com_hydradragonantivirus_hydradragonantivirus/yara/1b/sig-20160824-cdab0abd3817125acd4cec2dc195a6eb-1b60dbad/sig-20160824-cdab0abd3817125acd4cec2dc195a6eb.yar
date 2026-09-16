rule sig_20160824_cdab0abd3817125acd4cec2dc195a6eb {
  meta:
    description = "datamaliciousorder - file 20160824_cdab0abd3817125acd4cec2dc195a6eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff1470551e3b41346efaef62027f38fe648f26c73a5d0740382827374c2a88ab"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}