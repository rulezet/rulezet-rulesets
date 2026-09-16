rule sig_20160824_f410614b5dee1149eb1d0c52e3e736b6 {
  meta:
    description = "datamaliciousorder - file 20160824_f410614b5dee1149eb1d0c52e3e736b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d92183606bc01427d2b61d0593c615593ad8de7ebdc872494cc888d6a16506b"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}