rule _20160517_23b7c25b943032a45e9e42c2505cc2c0_20160517_375f2681bf5e_1241 {
  meta:
    description = "datamaliciousorder - from files 20160517_23b7c25b943032a45e9e42c2505cc2c0.js, 20160517_375f2681bf5ea0e27fddfcd261351c99.js, 20160517_397b88557ee1c19e069b4a1ef5120e8c.js, 20160517_96e41d104541fa6c321fb32da0831d4a.js, 20160517_ddf5deca11a453862774753ec1ccf62c.js, 20160517_f231b761ad3f65e8b8c769bd696e6f09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a65d552060bbd7efea6a5b32fc6fffea2115f3159c24ae22528b06641dd3449"
    hash2       = "c309164ff05b87b7d7ccd62c22b895f5e224982a9cc2dcbd593e58678b9cc102"
    hash3       = "7690c2b0c07d6b1d08aa1dbfadf3e427f5998badcb1290697e549030721b3235"
    hash4       = "1d4d0290c42903db326d03187be6d5eca3417397bff9ce56913dee9eddd7f45e"
    hash5       = "0125eda2a6a976c206bbde7444c605482ad12821df14d076d17eeedcc35491f6"
    hash6       = "f43cee11941c3ae6063e6488a51ec963fe611f5a3e025cd144a274d2f2b24b94"

  strings:
    $s1 = "function Scott /* j  */(accinp0 /* j  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "devel1[aaa](Turkey0 /* j  */, Currency, (true, false));" fullword ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* j  */ = (123, Turkey); return devel0 /* j  */;};" fullword ascii
    $s4 = "function Scott /* j  */(accinp0 /* j  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s5 = "DENMARK1 /* j  */= true;/* j  */" fullword ascii
    $s6 = "place = /* j  */(/* j  */\"noitisop\").split(''/* j  */).reverse(/* j  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}