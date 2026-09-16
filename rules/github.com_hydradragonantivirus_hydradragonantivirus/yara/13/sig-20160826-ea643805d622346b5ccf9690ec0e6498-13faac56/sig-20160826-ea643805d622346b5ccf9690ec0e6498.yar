rule sig_20160826_ea643805d622346b5ccf9690ec0e6498 {
  meta:
    description = "datamaliciousorder - file 20160826_ea643805d622346b5ccf9690ec0e6498.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba096b961cc4f3d0be609a1820fb7d5779e3813559393996136a89b6ddee5ac9"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}