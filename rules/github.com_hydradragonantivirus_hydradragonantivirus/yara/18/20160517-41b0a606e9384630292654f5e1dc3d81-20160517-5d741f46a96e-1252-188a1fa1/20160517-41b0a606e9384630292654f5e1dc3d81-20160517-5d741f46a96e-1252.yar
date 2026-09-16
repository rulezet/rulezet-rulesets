rule _20160517_41b0a606e9384630292654f5e1dc3d81_20160517_5d741f46a96e_1252 {
  meta:
    description = "datamaliciousorder - from files 20160517_41b0a606e9384630292654f5e1dc3d81.js, 20160517_5d741f46a96ea180424248f38639e6b0.js, 20160517_5de6141f525c35613a716ff9223a0d5d.js, 20160517_cf2f89288e98f1e42de43406610aa8d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "048e3075a371982e08ff53e1a4e293a8ed69243d33dc4e0a126e560b68e21817"
    hash2       = "f653526211f54f30222ebd00fdc4f72434ece15d4533060c5b92e819e7311273"
    hash3       = "44679f7deb19dd81bfe8c52ff4ef50a4e2e706f5310865548bf4c75013d00101"
    hash4       = "bc6c38860812c955531c815e78e24ff9e0b93032b27405f509aa7a8d99d1701f"

  strings:
    $s1 = "function Scott /* E  */(accinp0 /* E  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* E  */ = (123, Turkey); return devel0 /* E  */;};" fullword ascii
    $s3 = "devel1[aaa](Turkey0 /* E  */, Currency, (true, false));" fullword ascii
    $s4 = "function Scott /* E  */(accinp0 /* E  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s5 = "DENMARK1 /* E  */= true;/* E  */" fullword ascii
    $s6 = "place = /* E  */(/* E  */\"noitisop\").split(''/* E  */).reverse(/* E  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}