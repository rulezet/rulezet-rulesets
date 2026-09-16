rule sig_20160826_2c742d95a168d83a8025734fa6972cb2 {
  meta:
    description = "datamaliciousorder - file 20160826_2c742d95a168d83a8025734fa6972cb2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e0b36c4827d85359dda33469a94c3520bd22c6c974697bb18c44c692ac5f88a"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}