rule sig_20160826_72dab44553a2d7611f8c5ac9ef0e961e {
  meta:
    description = "datamaliciousorder - file 20160826_72dab44553a2d7611f8c5ac9ef0e961e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "210fe55dbadba75b9d903ae117c5b2acede7198f32858c028c0f86aabc863273"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}