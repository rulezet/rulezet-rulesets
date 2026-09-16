rule sig_20161010_0fccb95d4415a8d0a41d293d1de3edf7 {
  meta:
    description = "datamaliciousorder - file 20161010_0fccb95d4415a8d0a41d293d1de3edf7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc62f8fd7ed6dc6c02344da62efe65ef3bb371d90d36d89b99b15628b932f96e"

  strings:
    $s1  = "if (iknagm == undefined) {" fullword ascii
    $s2  = "function nazhobvok() {" fullword ascii
    $s3  = "var ovopy = typeof undefined;" fullword ascii
    $s4  = "function fmuzry() {" fullword ascii
    $s5  = "function ipunumi() {" fullword ascii
    $s6  = "var ypurrimikb = false;" fullword ascii
    $s7  = "return ycixe;" fullword ascii
    $s8  = "var bezitsybi = null;" fullword ascii
    $s9  = "return emlyzlyhy;" fullword ascii
    $s10 = "var wyrluvso = typeof undefined;" fullword ascii
    $s11 = "function mucjar() {" fullword ascii
    $s12 = "var lhyvqycyj = undefined;" fullword ascii
    $s13 = "function nicyvzuhe() {" fullword ascii
    $s14 = "return \"oubl\";" fullword ascii
    $s15 = "function ttojkumzom() {" fullword ascii
    $s16 = "return dbotmahwurja;" fullword ascii
    $s17 = "var widokp = typeof undefined;" fullword ascii
    $s18 = "function exlewjobruf() {" fullword ascii
    $s19 = "return bjytwak;" fullword ascii
    $s20 = "var ifhujhy = typeof undefined;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}