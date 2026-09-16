rule _20160516_1d236335f76e61b028a58274bf1883cd_20160516_6188299c9fb1_1221 {
  meta:
    description = "datamaliciousorder - from files 20160516_1d236335f76e61b028a58274bf1883cd.js, 20160516_6188299c9fb1d4d7b6a6b03d0c5ec4fd.js, 20160516_ca834418611afa44d2627644bbaeed9e.js, 20160517_6729598c961ab62b00e7b0b0d9e85b33.js, 20160517_b0eef7a316558e500049e44b265d3df1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc74bf3531d1a9791ac038d693fd84571f1e4f99002255164d23cb90d9c8075c"
    hash2       = "bef1178149229912ed2042a785e389dd5a97bdb11e729fd13cb0361c83a71d86"
    hash3       = "11a934888cbf30568261f63c84391ba08a0ad60d7e699b1503c25446b2078221"
    hash4       = "75fc88388a573751dfbbcc986c826d0b164249267433572a21c41a404e0cb75b"
    hash5       = "7160acc13e83f5cfe05db3f2be34b2ceb911870438394cc207d283ee74f57ed6"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* r  */, Currency, (true, false));" fullword ascii
    $s2 = "function Scott /* r  */(accinp0 /* r  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* r  */ = (123, Turkey); return devel0 /* r  */;};" fullword ascii
    $s4 = "function Scott /* r  */(accinp0 /* r  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s5 = "DENMARK1 /* r  */= true;/* r  */" fullword ascii
    $s6 = "place = /* r  */(/* r  */\"noitisop\").split(''/* r  */).reverse(/* r  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}