rule sig_20160824_8d08ed9d9ade31e62d8d1bc7d07eec13 {
  meta:
    description = "datamaliciousorder - file 20160824_8d08ed9d9ade31e62d8d1bc7d07eec13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06ad8269ba724e0f147d99e63e7bd5251ca9cff8de24606ea491f494f840dddf"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}