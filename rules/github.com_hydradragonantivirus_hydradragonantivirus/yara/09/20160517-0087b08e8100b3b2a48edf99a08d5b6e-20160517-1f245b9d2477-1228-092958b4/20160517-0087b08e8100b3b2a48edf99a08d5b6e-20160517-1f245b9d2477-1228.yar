rule _20160517_0087b08e8100b3b2a48edf99a08d5b6e_20160517_1f245b9d2477_1228 {
  meta:
    description = "datamaliciousorder - from files 20160517_0087b08e8100b3b2a48edf99a08d5b6e.js, 20160517_1f245b9d2477632eb63fd0eaa13c1c91.js, 20160517_39490aa375b5b6695e2cb76e6226c9c5.js, 20160517_3d8c6490435938ba49e8b1910ce1d1fc.js, 20160517_3f647636c6553e45fde928d49ee1b871.js, 20160517_66e765ad6ad217719cbbd67c682691ac.js, 20160517_7024e10d61fd87c9f6fb119a3500bf81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "291272977b6b45a27a46d96d2f40ec2ea70108b1ce37c3f515d074eac39f558e"
    hash2       = "b67af859af735201b94ed6214a5925b2d5432abfff0535612cb070d9645aef5f"
    hash3       = "76664645a6fec4a5ff79e103be976ece50f6fb1477399cf03b68fce63463880c"
    hash4       = "f0f2ea145461dd111c3853749084b9495c1c14890c2922204796f97cb23e9747"
    hash5       = "325d7727e89ae5459cd30b3312a60222c1fd54a2fd5ca565774e119535947a88"
    hash6       = "fff644c8948d5836a86a0fd2fa792fdcdafecf45da2f75c90d6e464891e74bc7"
    hash7       = "8a42ca9ab23f1035e43ce79d6b98aa3b65ec43d59abf3e54718511dba9dbfaaf"

  strings:
    $s1 = "function Scott /* B  */(accinp0 /* B  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "devel1[aaa](Turkey0 /* B  */, Currency, (true, false));" fullword ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* B  */ = (123, Turkey); return devel0 /* B  */;};" fullword ascii
    $s4 = "function Scott /* B  */(accinp0 /* B  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s5 = "place = /* B  */(/* B  */\"noitisop\").split(''/* B  */).reverse(/* B  */).join('');" fullword ascii
    $s6 = "DENMARK1 /* B  */= true;/* B  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}