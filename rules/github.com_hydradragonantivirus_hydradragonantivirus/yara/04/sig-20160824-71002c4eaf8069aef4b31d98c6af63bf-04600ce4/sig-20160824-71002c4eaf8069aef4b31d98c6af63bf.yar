rule sig_20160824_71002c4eaf8069aef4b31d98c6af63bf {
  meta:
    description = "datamaliciousorder - file 20160824_71002c4eaf8069aef4b31d98c6af63bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a5c5b7cce4a31c375885841e5f84620e51b4b3ce2adf380fc4c6227f58359ed"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}