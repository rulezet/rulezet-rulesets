rule sig_20160826_ee093937e49164da7937919125173836 {
  meta:
    description = "datamaliciousorder - file 20160826_ee093937e49164da7937919125173836.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31662e1c21718b3cf638e03dacca1e06341634913a84d3f017a53f2eca0a0342"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}