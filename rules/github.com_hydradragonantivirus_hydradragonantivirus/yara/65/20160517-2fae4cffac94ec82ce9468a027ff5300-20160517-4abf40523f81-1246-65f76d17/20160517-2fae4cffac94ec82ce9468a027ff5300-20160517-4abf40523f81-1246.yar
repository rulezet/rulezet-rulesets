rule _20160517_2fae4cffac94ec82ce9468a027ff5300_20160517_4abf40523f81_1246 {
  meta:
    description = "datamaliciousorder - from files 20160517_2fae4cffac94ec82ce9468a027ff5300.js, 20160517_4abf40523f812d467c920295fffd1d5c.js, 20160517_66c2af3ef007068fec81c9d817dec6c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a42f99fe8cdb1934b96c6eec2212e0709fe0348b30a8d79899dab2e15a8b008"
    hash2       = "5845f06f8c5107ef5ad0dc7c5bd641f3d99fec83a688dc192606a695c0a9bc71"
    hash3       = "8a1ad698ecacb33fb45547a3dbb093aa92ff0774d0620831e93a6a4330b38567"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* t  */, Currency, (true, false));" fullword ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* t  */ = (123, Turkey); return devel0 /* t  */;};" fullword ascii
    $s3 = "function Scott /* t  */(accinp0 /* t  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s4 = "function Scott /* t  */(accinp0 /* t  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s5 = "place = /* t  */(/* t  */\"noitisop\").split(''/* t  */).reverse(/* t  */).join('');" fullword ascii
    $s6 = "DENMARK1 /* t  */= true;/* t  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}