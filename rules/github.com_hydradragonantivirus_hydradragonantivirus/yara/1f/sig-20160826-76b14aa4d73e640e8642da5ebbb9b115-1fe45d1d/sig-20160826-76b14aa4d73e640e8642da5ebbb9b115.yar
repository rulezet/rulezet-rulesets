rule sig_20160826_76b14aa4d73e640e8642da5ebbb9b115 {
  meta:
    description = "datamaliciousorder - file 20160826_76b14aa4d73e640e8642da5ebbb9b115.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7e0322d5d7a4a519c0a8c86fe6ed750a46cabb158d52c511d652d89a10fccb5"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}