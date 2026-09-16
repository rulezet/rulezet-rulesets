rule _20160517_2ffb759660e7d4b8c70a1cca529df72e_20160517_353e4815f56c_1247 {
  meta:
    description = "datamaliciousorder - from files 20160517_2ffb759660e7d4b8c70a1cca529df72e.js, 20160517_353e4815f56c8242878a4f526ed9c36b.js, 20160517_4b7c55e6c77dab2d428d8144c9d87703.js, 20160517_76c0ca1d11d81f0077182e6e5c2dbd85.js, 20160517_e346c0415c9b659d8f8af0b0d05db830.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfcbead9952c786a099b39dfd5acb200551d8a271d57b8cfa5f0cd9232c5a100"
    hash2       = "b9de869a6dde046d904d9b078bf85c442146df4660d9f7e1a59a9cd573e2c605"
    hash3       = "4fcedd8a5c84831c2fbab687c56647a294d3e138652d012c1251d55c5cc8cfd2"
    hash4       = "07d0023814c05728f90306c2b97cc031e24f7bad482d014114ad71d72770b207"
    hash5       = "d82d3885c599580510ebc989d72d5950df11735aec7345ab67d515cce8bc9473"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* g  */, Currency, (true, false));" fullword ascii
    $s2 = "function Scott /* g  */(accinp0 /* g  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* g  */ = (123, Turkey); return devel0 /* g  */;};" fullword ascii
    $s4 = "function Scott /* g  */(accinp0 /* g  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s5 = "place = /* g  */(/* g  */\"noitisop\").split(''/* g  */).reverse(/* g  */).join('');" fullword ascii
    $s6 = "DENMARK1 /* g  */= true;/* g  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}