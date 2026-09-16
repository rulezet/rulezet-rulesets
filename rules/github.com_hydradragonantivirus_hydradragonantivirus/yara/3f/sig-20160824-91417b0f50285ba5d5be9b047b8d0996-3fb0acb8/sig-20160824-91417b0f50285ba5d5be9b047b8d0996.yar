rule sig_20160824_91417b0f50285ba5d5be9b047b8d0996 {
  meta:
    description = "datamaliciousorder - file 20160824_91417b0f50285ba5d5be9b047b8d0996.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c265d5bc4be40923e5d4738e7e59cc901b78fec0142bfd020b23144dc0b7196"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}