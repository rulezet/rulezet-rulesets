rule _20160517_14d08a9ae081077e81db242655153c4b_20160517_6eaba043e551_976 {
  meta:
    description = "datamaliciousorder - from files 20160517_14d08a9ae081077e81db242655153c4b.js, 20160517_6eaba043e5514107849fabbfcb2d3d80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1113580f008d27386f794d014417f86c5d528ad21f49a4443d6723def8de963"
    hash2       = "6fe0441df8c9236e55865f0c4f73645d8bc6c8c02f650d415a730ac4dae3114d"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* Kr  */, Currency, (true, false));" fullword ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* Kr  */ = (123, Turkey); return devel0 /* Kr  */;};" fullword ascii
    $s3 = "function Scott /* Kr  */(accinp0 /* Kr  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 " ascii
    $s4 = "function Scott /* Kr  */(accinp0 /* Kr  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 " ascii
    $s5 = "DENMARK1 /* Kr  */= true;/* Kr  */" fullword ascii
    $s6 = "place = /* Kr  */(/* Kr  */\"noitisop\").split(''/* Kr  */).reverse(/* Kr  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}