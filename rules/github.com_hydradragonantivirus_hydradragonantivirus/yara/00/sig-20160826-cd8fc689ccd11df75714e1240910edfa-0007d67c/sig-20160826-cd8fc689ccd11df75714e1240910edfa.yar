rule sig_20160826_cd8fc689ccd11df75714e1240910edfa {
  meta:
    description = "datamaliciousorder - file 20160826_cd8fc689ccd11df75714e1240910edfa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b36da58e1c36f4c54ed0938cfe31f9b72d4e13278efdc71e00a00b7ebbbc3f03"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}