rule _20160517_c517504979a5e10712c7580224ed5051_20160517_d6785a4f7d5d_1267 {
  meta:
    description = "datamaliciousorder - from files 20160517_c517504979a5e10712c7580224ed5051.js, 20160517_d6785a4f7d5dae7e3e33fe797b1771b4.js, 20160517_e29b960ebf0d28ade3c2829679bef068.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "219640daa653733e8129b4e5be3b929c0c74de26a1de799c4fd2c8d38f1ebaa9"
    hash2       = "a334d7e595096e39384078c958731960e694396b09c070c37082420461acd76c"
    hash3       = "56ed5717e6cd97fe6c734a84fb6e8cf4755c263e82f544386f41329d48bd1780"

  strings:
    $s1 = "function Scott /* V  */(accinp0 /* V  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "devel1[aaa](Turkey0 /* V  */, Currency, (true, false));" fullword ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* V  */ = (123, Turkey); return devel0 /* V  */;};" fullword ascii
    $s4 = "function Scott /* V  */(accinp0 /* V  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s5 = "place = /* V  */(/* V  */\"noitisop\").split(''/* V  */).reverse(/* V  */).join('');" fullword ascii
    $s6 = "DENMARK1 /* V  */= true;/* V  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}