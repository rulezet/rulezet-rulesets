rule _20160517_0cd658093cca3619302c5f72011aecab_20160517_2307d5598dc3_1236 {
  meta:
    description = "datamaliciousorder - from files 20160517_0cd658093cca3619302c5f72011aecab.js, 20160517_2307d5598dc382151d2d7454ecbed6db.js, 20160517_76b4f79767e7f516b5f4ff5c9ace29dd.js, 20160517_aa2de103451938062925afff90669cdf.js, 20160517_d9c476dc54468d0a8419cc091e60514c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19f499d045bb86dfc1c409c1f0507b484e0a8d477ca03a207dd3d0a24062bb53"
    hash2       = "28e485dad94a5e5939d418ebc290d449448ea0038ed106d30a01720939e308c2"
    hash3       = "307cf730183056247a53272bf5d87675e85eed8a84da2089798657e8a2f37828"
    hash4       = "d5f457f78d43f1bec7f3ecf9227ee35c7ee9783bf895f234b79bd1c74ff63927"
    hash5       = "e8c5842081f0c0d9c2835840279b23a0d966fef7f40e59fb5175693814429ce8"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* p  */, Currency, (true, false));" fullword ascii
    $s2 = "function Scott /* p  */(accinp0 /* p  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* p  */ = (123, Turkey); return devel0 /* p  */;};" fullword ascii
    $s4 = "DENMARK1 /* p  */= true;/* p  */" fullword ascii
    $s5 = "function Scott /* p  */(accinp0 /* p  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s6 = "place = /* p  */(/* p  */\"noitisop\").split(''/* p  */).reverse(/* p  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}