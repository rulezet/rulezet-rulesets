rule _20170126_d72a6de9c72457b606f08f248c9950d1_20170126_ef30c8100245_1754 {
  meta:
    description = "datamaliciousorder - from files 20170126_d72a6de9c72457b606f08f248c9950d1.js, 20170126_ef30c8100245f175810c698a9832683d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec6545be81e9d886c2c4ff2ae3423abdf3f0727c181b987b85e98ee77802dc60"
    hash2       = "dffda8320ab2cb51869c88e87e6158d14eb0e3b139c96431289c95c20342ffea"

  strings:
    $s1  = "return [\".Fi\", ''];" fullword ascii
    $s2  = "return ['', '', '', '', \"hv\"];" fullword ascii
    $s3  = "return ['', \"T\"];" fullword ascii
    $s4  = "return [\"leS\", '', ''];" fullword ascii
    $s5  = "return [\"e\", '', '', '', ''];" fullword ascii
    $s6  = "return ['', '', \"-2\", ''];" fullword ascii
    $s7  = "return [\"Fil\", '', ''];" fullword ascii
    $s8  = "return ['', \"TP\", '', '', ''];" fullword ascii
    $s9  = "return [\"Ob\", '', '', '', ''];" fullword ascii
    $s10 = "return ['', \"g.\"];" fullword ascii
    $s11 = "return ['', \"Fil\", '', ''];" fullword ascii

  condition:
    (uint16(0) == 0x7566 and (8 of them)
    ) or (all of them)
}