rule sig_20160525_5e99867e4f51f5c651921f869731a192 {
  meta:
    description = "datamaliciousorder - file 20160525_5e99867e4f51f5c651921f869731a192.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2e3e584791fe8171a83825cdf9551e15212986d4d927c6963b5bd95457278be"

  strings:
    $s1 = "nruter{)(tsilslianbmuhtoh noitcnuf( + tsilslianbmuhtog + ssorcag + sdnetg[tpircSW = gsmb rav    \\n{\\n)ima ,tsilslianbmuhtoa(su" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}