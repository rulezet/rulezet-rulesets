rule sig_20160826_87ee72f65031fb6b3cb0b57e36dab407 {
  meta:
    description = "datamaliciousorder - file 20160826_87ee72f65031fb6b3cb0b57e36dab407.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5a0e03e107d36df43ab9c81c55cf8f057cb1b2d61fab123f110af1e42816abe"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}