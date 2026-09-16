rule sig_20160824_5b2b70e0b394fc549eb5194678709fbe {
  meta:
    description = "datamaliciousorder - file 20160824_5b2b70e0b394fc549eb5194678709fbe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c742753e6553e1a546f62cc2d826e648f13dec689d93db468b8c1337787c0292"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}