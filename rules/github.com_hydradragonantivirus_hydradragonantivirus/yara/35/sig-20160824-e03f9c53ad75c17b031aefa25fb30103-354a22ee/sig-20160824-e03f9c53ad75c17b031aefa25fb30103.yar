rule sig_20160824_e03f9c53ad75c17b031aefa25fb30103 {
  meta:
    description = "datamaliciousorder - file 20160824_e03f9c53ad75c17b031aefa25fb30103.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d96ad5e77fe73947f823144a8b819bac02943eb46938def778283840b03a5a5"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}