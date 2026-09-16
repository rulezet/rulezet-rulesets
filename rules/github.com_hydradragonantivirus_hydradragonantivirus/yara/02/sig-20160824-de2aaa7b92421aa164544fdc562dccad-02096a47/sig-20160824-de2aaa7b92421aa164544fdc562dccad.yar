rule sig_20160824_de2aaa7b92421aa164544fdc562dccad {
  meta:
    description = "datamaliciousorder - file 20160824_de2aaa7b92421aa164544fdc562dccad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53297f6f8e19aba9ea0083df3aba870fb430116aa9a3523caa9def7ace45557f"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}