rule sig_20160824_384ca2f0fcbe5587de45ccf1b32be327 {
  meta:
    description = "datamaliciousorder - file 20160824_384ca2f0fcbe5587de45ccf1b32be327.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2246c4e1aab1acb8811751b0b2848ac28c776024d5b876972ebf1840e803ae1a"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}