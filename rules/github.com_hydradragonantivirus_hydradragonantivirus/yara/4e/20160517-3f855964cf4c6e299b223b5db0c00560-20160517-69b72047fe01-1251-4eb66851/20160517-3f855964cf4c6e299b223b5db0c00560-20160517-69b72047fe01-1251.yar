rule _20160517_3f855964cf4c6e299b223b5db0c00560_20160517_69b72047fe01_1251 {
  meta:
    description = "datamaliciousorder - from files 20160517_3f855964cf4c6e299b223b5db0c00560.js, 20160517_69b72047fe018af56200fbbd94b8ff81.js, 20160517_b19ceb61e05b0482096e0e3ecf0b7a50.js, 20160517_eefc91fbcd3305d7bc5c511938f6701a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9c47665050c9a4b1d81168ec320d1aacc2d2660d273096703ccedcbd3685997"
    hash2       = "a35f1c47eecaf91c90d492019dac801f7269e87d863b7594e92fa7ad6e50b2c2"
    hash3       = "43007021bf1374a3b1a6377b230306cd6953d4814681d3b0dd3ce3fbee39e9ee"
    hash4       = "02cd30942ca16ec1f18226cc1c2a3f3bb360f41578482242bfbeebb2eb913219"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* e  */, Currency, (true, false));" fullword ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* e  */ = (123, Turkey); return devel0 /* e  */;};" fullword ascii
    $s3 = "function Scott /* e  */(accinp0 /* e  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s4 = "function Scott /* e  */(accinp0 /* e  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s5 = "DENMARK1 /* e  */= true;/* e  */" fullword ascii
    $s6 = "place = /* e  */(/* e  */\"noitisop\").split(''/* e  */).reverse(/* e  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}