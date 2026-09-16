rule _20160517_2192e11b23f8e77502fd5d198bffadf9_20160517_220564b072de_1240 {
  meta:
    description = "datamaliciousorder - from files 20160517_2192e11b23f8e77502fd5d198bffadf9.js, 20160517_220564b072de0f990462b08d2419827b.js, 20160517_f5a02daf76c346df213a48dab0e743ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bde5b4e00f396a5d4a4820e41c039e259228d218e521cdf5fb09c8be099df32b"
    hash2       = "80c0cf3a098058faf8ae4395f24a5285ddd2bd8d430eb733083f1f0c3a01a37d"
    hash3       = "7d60266be95164992d3a0eece40a1df20fb30040d982fb6dc8ccf5e8bb217c98"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* h  */, Currency, (true, false));" fullword ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* h  */ = (123, Turkey); return devel0 /* h  */;};" fullword ascii
    $s3 = "function Scott /* h  */(accinp0 /* h  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s4 = "DENMARK1 /* h  */= true;/* h  */" fullword ascii
    $s5 = "place = /* h  */(/* h  */\"noitisop\").split(''/* h  */).reverse(/* h  */).join('');" fullword ascii
    $s6 = "function Scott /* h  */(accinp0 /* h  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}