rule sig_20160514_3785f137fb46d3ed1f17ec758c07efd1 {
  meta:
    description = "datamaliciousorder - file 20160514_3785f137fb46d3ed1f17ec758c07efd1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f920fa9ecabc5eeb9cf001a6172d4179cbe318ac6aeee9c8398c1e747503d547"

  strings:
    $s1  = "while (uMLfTO < gUsdLqC - (2523 + 2048 - 4569)) {" fullword ascii
    $s2  = "function NwIhaN(updLepII) {" fullword ascii
    $s3  = "return lIlCW;" fullword ascii
    $s4  = "if (uYt === false) {" fullword ascii
    $s5  = "function NHxMMNq() {" fullword ascii
    $s6  = "var dDnuRej = true;" fullword ascii
    $s7  = "return OHidoAxR;" fullword ascii
    $s8  = "return IoLLmp;" fullword ascii
    $s9  = "return hdXEL;" fullword ascii
    $s10 = "return zHIQod;" fullword ascii
    $s11 = "function rgjDi() {" fullword ascii
    $s12 = "return mkai;" fullword ascii
    $s13 = "function oGDBd() {" fullword ascii
    $s14 = "function wBj() {" fullword ascii
    $s15 = "function SVeXNn() {" fullword ascii
    $s16 = "var otJUSCU = true;" fullword ascii
    $s17 = "return NXBwsa;" fullword ascii
    $s18 = "function RiC() {" fullword ascii
    $s19 = "return cwAxLh;" fullword ascii
    $s20 = "return ffqMNz;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}