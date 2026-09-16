rule sig_20160824_f72498cff04df6872a11651e8a672dd9 {
  meta:
    description = "datamaliciousorder - file 20160824_f72498cff04df6872a11651e8a672dd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "743148584383edd367245aec7871555fe946c2e982ef4870df929cc600d48f77"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}