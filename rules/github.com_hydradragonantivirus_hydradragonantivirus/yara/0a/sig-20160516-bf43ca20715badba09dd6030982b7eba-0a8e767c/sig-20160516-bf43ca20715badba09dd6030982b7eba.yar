rule sig_20160516_bf43ca20715badba09dd6030982b7eba {
  meta:
    description = "datamaliciousorder - file 20160516_bf43ca20715badba09dd6030982b7eba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b29f1821d096c7c7c3f75bf5a8085247ce25331a07ed035c68b7f868bb38e613"

  strings:
    $s1 = "var aoui='vobblmavntohrknlmc dwkfohxabkq4phwpd2zdjusgsggtzduoncaqqo1dywui3vwonseph=jepy3\\'lyjrstnigzpcgtel2nibjf1ie4sotfda2t4uu" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}