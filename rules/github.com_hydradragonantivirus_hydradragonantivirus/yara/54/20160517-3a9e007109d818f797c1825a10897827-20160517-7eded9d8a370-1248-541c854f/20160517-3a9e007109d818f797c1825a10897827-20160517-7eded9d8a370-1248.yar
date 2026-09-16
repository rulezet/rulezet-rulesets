rule _20160517_3a9e007109d818f797c1825a10897827_20160517_7eded9d8a370_1248 {
  meta:
    description = "datamaliciousorder - from files 20160517_3a9e007109d818f797c1825a10897827.js, 20160517_7eded9d8a3708b832a3651e0d5f9d833.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "214188cacc15efdd835e31ae5c90696ab6c82220b2cc9194d4f356cac1924c54"
    hash2       = "b1a96cb43596378f0b0bc5a3e0f7185b8e2dea48c6a885527ddcb702f41279b6"

  strings:
    $s1 = "function DENMARK(Turkey) {var devel0 /* P  */ = (123, Turkey); return devel0 /* P  */;};" fullword ascii
    $s2 = "devel1[aaa](Turkey0 /* P  */, Currency, (true, false));" fullword ascii
    $s3 = "function Scott /* P  */(accinp0 /* P  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s4 = "place = /* P  */(/* P  */\"noitisop\").split(''/* P  */).reverse(/* P  */).join('');" fullword ascii
    $s5 = "DENMARK1 /* P  */= true;/* P  */" fullword ascii
    $s6 = "function Scott /* P  */(accinp0 /* P  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}