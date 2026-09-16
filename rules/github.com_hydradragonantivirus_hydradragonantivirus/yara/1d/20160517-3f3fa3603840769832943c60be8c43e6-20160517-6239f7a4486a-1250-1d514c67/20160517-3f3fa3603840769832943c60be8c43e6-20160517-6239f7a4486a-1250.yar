rule _20160517_3f3fa3603840769832943c60be8c43e6_20160517_6239f7a4486a_1250 {
  meta:
    description = "datamaliciousorder - from files 20160517_3f3fa3603840769832943c60be8c43e6.js, 20160517_6239f7a4486a96c305283cae346b448f.js, 20160517_a3800940ef7096638b48839553018015.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb62ebb99d030a8a2bd53050a7439857a76edffa02207f89071b2127f465e7bc"
    hash2       = "ac7bb758371c9cbcac9f31f95a835b6ebebabf05bdfa99fee064ee889a48956b"
    hash3       = "f4343913069db58c39366288fd7352a7f00ac5a2db4dc94ed2452bef4352cf0d"

  strings:
    $s1 = "function Scott /* K  */(accinp0 /* K  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* K  */ = (123, Turkey); return devel0 /* K  */;};" fullword ascii
    $s3 = "devel1[aaa](Turkey0 /* K  */, Currency, (true, false));" fullword ascii
    $s4 = "place = /* K  */(/* K  */\"noitisop\").split(''/* K  */).reverse(/* K  */).join('');" fullword ascii
    $s5 = "DENMARK1 /* K  */= true;/* K  */" fullword ascii
    $s6 = "function Scott /* K  */(accinp0 /* K  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}