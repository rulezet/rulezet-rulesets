rule _20160517_07abe70125c7d5f4dda32e1bb1e01849_20160517_082b475d1043_1233 {
  meta:
    description = "datamaliciousorder - from files 20160517_07abe70125c7d5f4dda32e1bb1e01849.js, 20160517_082b475d10436f45800e36560e523d13.js, 20160517_4161db15d5a868340dbd0540016b1d61.js, 20160517_50b62235dac69699313ac37d08328b6a.js, 20160517_6150dbc23004255fc63c60665cb6c6dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c29f9f45cceb3813b1d4287a22ed428f5c8c3a1569f56e7c42266434aa68bfb5"
    hash2       = "a9fbf97728404350596cb67dff85d575469da0eb51bce96c907b0c89ee406d5f"
    hash3       = "9832524abfaf07b17946673f8297158e342168ed9da3b1478f96ff0e9e336e06"
    hash4       = "433033e147d0e364813ce93b09df079af47151cd518e6a785d717a0e58c66fb2"
    hash5       = "27031f093d073ad8755458abec66a6770e957a8a4555b328c173c1a94eb50156"

  strings:
    $s1 = "function DENMARK(Turkey) {var devel0 /* l  */ = (123, Turkey); return devel0 /* l  */;};" fullword ascii
    $s2 = "function Scott /* l  */(accinp0 /* l  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s3 = "devel1[aaa](Turkey0 /* l  */, Currency, (true, false));" fullword ascii
    $s4 = "function Scott /* l  */(accinp0 /* l  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s5 = "place = /* l  */(/* l  */\"noitisop\").split(''/* l  */).reverse(/* l  */).join('');" fullword ascii
    $s6 = "DENMARK1 /* l  */= true;/* l  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}