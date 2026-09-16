rule sig_20161128_8f6362656486c2fc95b471f8e3b7ce72 {
  meta:
    description = "datamaliciousorder - file 20161128_8f6362656486c2fc95b471f8e3b7ce72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8ecad07c8e978ab7ded1f499f5e481ce562c5fde5482c146e50e9c46c43aa01"

  strings:
    $s1  = "return new Function(ewhyqma + ifberq + \"object')[gxunmu]('C:\\\\\\\\')['type']['length'] > 1\");" fullword ascii
    $s2  = "var ifberq = \"Object('scripting.fileSystem\";" fullword ascii
    $s3  = "function uhuzp() {" fullword ascii
    $s4  = "var azadacp = true;" fullword ascii
    $s5  = "if (ivymkyvp() === null) {" fullword ascii
    $s6  = "return helabbywz;" fullword ascii
    $s7  = "var qbazywnif = undefined;" fullword ascii
    $s8  = "return ltukvu;" fullword ascii
    $s9  = "var jjameri = null;" fullword ascii
    $s10 = "function ikqihubaz() {" fullword ascii
    $s11 = "return qbazywnif;" fullword ascii
    $s12 = "switch (evceko()()) {" fullword ascii
    $s13 = "var igfow = false;" fullword ascii
    $s14 = "var zyzorazx = undefined;" fullword ascii
    $s15 = "return 98;" fullword ascii
    $s16 = "function evceko() {" fullword ascii
    $s17 = "var toxif = undefined;" fullword ascii
    $s18 = "var izokhagr = true;" fullword ascii
    $s19 = "var onlecpevemn = true;" fullword ascii
    $s20 = "return yckirdakg;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}