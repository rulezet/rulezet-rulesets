rule _20160517_0dbe95b9d90f63c1bebb09d13d8e1c9a_20160517_3e92e08d435c_1237 {
  meta:
    description = "datamaliciousorder - from files 20160517_0dbe95b9d90f63c1bebb09d13d8e1c9a.js, 20160517_3e92e08d435c9841c369d0eabcbb7bad.js, 20160517_a402579735b3dbee984b3e23301c8904.js, 20160517_a91059a122c0b3fab365903478c77604.js, 20160517_bb786586ffe8dce116bf04f69d231eaf.js, 20160517_e86593d508397f963d72a5b199a23fb2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9981f69f1fa9928430f351461c9b4138ad75dcca0351baa342b1e294db6b83b5"
    hash2       = "e34aca9659184ad537e8f629c6c816725525cbd802165e66bb24e6fadcd0f5de"
    hash3       = "b3593395cf45f7c3b95f1e5cf125bbac1625e3b98c3625682a9537167743a3a7"
    hash4       = "3e09afa7e880e6fedfdf9a8c1af2aa40a7e2741386a731a9218520613806147a"
    hash5       = "71d9bdcdf18f90100bca246e7989c2d928506b436cbbb9c624cbec5f3470f8d0"
    hash6       = "04a94945bc0eaca9281fe8f66db0c1d87c505fb08a4c526b39c6f66374327189"

  strings:
    $s1 = "function DENMARK(Turkey) {var devel0 /* u  */ = (123, Turkey); return devel0 /* u  */;};" fullword ascii
    $s2 = "function Scott /* u  */(accinp0 /* u  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s3 = "devel1[aaa](Turkey0 /* u  */, Currency, (true, false));" fullword ascii
    $s4 = "function Scott /* u  */(accinp0 /* u  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s5 = "place = /* u  */(/* u  */\"noitisop\").split(''/* u  */).reverse(/* u  */).join('');" fullword ascii
    $s6 = "DENMARK1 /* u  */= true;/* u  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}