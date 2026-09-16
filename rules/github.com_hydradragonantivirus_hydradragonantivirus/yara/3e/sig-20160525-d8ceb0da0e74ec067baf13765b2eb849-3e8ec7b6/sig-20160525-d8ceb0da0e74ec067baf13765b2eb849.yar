rule sig_20160525_d8ceb0da0e74ec067baf13765b2eb849 {
  meta:
    description = "datamaliciousorder - file 20160525_d8ceb0da0e74ec067baf13765b2eb849.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d4d74aaeb1559ee0f2bd4e5d0b414d9b676f5d4119bcfc9fd972aecc93d7103"

  strings:
    $s1 = "};tsilslianbmuhtog nruter{)(ssorcah noitcnuf( + ssorcag + sdnetg + deerdg[tpircSW = gsmb rav    \\n{\\n)ima ,tsilslianbmuhtoa(su" ascii
    $s2 = "76x\\\\n56x\\\\l\" = gedotdarl rav\\n;\"h47x\\\\\" = keppell rav\\n;\"e6x\\\\es\" = modnarl rav\\n;)4(]\"tAra\"+\"86x\\\\\"+\"c" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}