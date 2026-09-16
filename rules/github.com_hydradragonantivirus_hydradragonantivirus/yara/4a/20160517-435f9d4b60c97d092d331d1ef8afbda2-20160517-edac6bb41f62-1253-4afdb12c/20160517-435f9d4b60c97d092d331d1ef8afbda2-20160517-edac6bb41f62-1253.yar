rule _20160517_435f9d4b60c97d092d331d1ef8afbda2_20160517_edac6bb41f62_1253 {
  meta:
    description = "datamaliciousorder - from files 20160517_435f9d4b60c97d092d331d1ef8afbda2.js, 20160517_edac6bb41f62d0d0156ff58d9a762e81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fab260314eb374443b6141e414ed492d5e9b27798f9a34a9a81961877c6c0b14"
    hash2       = "0b318d0f8e82e93b87c0a27c5bf13a3a725f96bbdae2afef5cc358ea4ff9667d"

  strings:
    $s1 = "function DENMARK(Turkey) {var devel0 /* d  */ = (123, Turkey); return devel0 /* d  */;};" fullword ascii
    $s2 = "function Scott /* d  */(accinp0 /* d  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s3 = "devel1[aaa](Turkey0 /* d  */, Currency, (true, false));" fullword ascii
    $s4 = "place = /* d  */(/* d  */\"noitisop\").split(''/* d  */).reverse(/* d  */).join('');" fullword ascii
    $s5 = "DENMARK1 /* d  */= true;/* d  */" fullword ascii
    $s6 = "function Scott /* d  */(accinp0 /* d  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}