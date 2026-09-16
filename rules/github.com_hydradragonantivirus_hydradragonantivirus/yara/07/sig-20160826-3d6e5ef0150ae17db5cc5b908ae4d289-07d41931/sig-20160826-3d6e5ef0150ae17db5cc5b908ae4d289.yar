rule sig_20160826_3d6e5ef0150ae17db5cc5b908ae4d289 {
  meta:
    description = "datamaliciousorder - file 20160826_3d6e5ef0150ae17db5cc5b908ae4d289.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a576467e4344e4629dd601466b952c0a4ab1b5ed98489f628fe31cd35236aebe"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}