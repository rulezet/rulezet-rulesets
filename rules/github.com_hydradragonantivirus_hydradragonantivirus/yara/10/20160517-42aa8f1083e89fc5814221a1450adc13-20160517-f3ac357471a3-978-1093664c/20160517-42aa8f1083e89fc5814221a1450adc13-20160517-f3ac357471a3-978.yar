rule _20160517_42aa8f1083e89fc5814221a1450adc13_20160517_f3ac357471a3_978 {
  meta:
    description = "datamaliciousorder - from files 20160517_42aa8f1083e89fc5814221a1450adc13.js, 20160517_f3ac357471a3221062adb47c0a498484.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b07c4ccabad06b55ffc0ca95164a6a57d2166d788290acb93234c835215da13"
    hash2       = "145e5f01801bb6f17ef6799c509544f56a3fd3fc2082224821a5d12a0609f72a"

  strings:
    $s1 = "function Scott /* uF  */(accinp0 /* uF  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 " ascii
    $s2 = "devel1[aaa](Turkey0 /* uF  */, Currency, (true, false));" fullword ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* uF  */ = (123, Turkey); return devel0 /* uF  */;};" fullword ascii
    $s4 = "place = /* uF  */(/* uF  */\"noitisop\").split(''/* uF  */).reverse(/* uF  */).join('');" fullword ascii
    $s5 = "DENMARK1 /* uF  */= true;/* uF  */" fullword ascii
    $s6 = "function Scott /* uF  */(accinp0 /* uF  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 " ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}