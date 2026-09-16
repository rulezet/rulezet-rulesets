rule sig_20160405_c74c5e2a1d6a48db503257918ab85c10 {
  meta:
    description = "datamaliciousorder - file 20160405_c74c5e2a1d6a48db503257918ab85c10.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aefe537c2fff76d80a0bdaa37aa5cc070cda72fb351410bcf756bb73a1f7c4b7"

  strings:
    $s1  = "while (cj < aWfpPyr.length - (995, 8649, 7223, 6998, 4654, 5108, 7057, 2)) {" fullword ascii
    $s2  = "switch (16546) {" fullword ascii
    $s3  = "function oSsb(aWfpPyr) {" fullword ascii
    $s4  = "print(zYzULi(\"1\"));" fullword ascii
    $s5  = "if (MyKG === false) {" fullword ascii
    $s6  = "if (gyqvfV === true) {" fullword ascii
    $s7  = "if (uUPIW == true) {" fullword ascii
    $s8  = "function qBC() {" fullword ascii
    $s9  = "function zYzULi() {" fullword ascii
    $s10 = "print (xVV);" fullword ascii
    $s11 = "function Rnax(MAZkTf, LayJTT) {" fullword ascii
    $s12 = "var qtzj = true;" fullword ascii
    $s13 = "print (aqiuPKi(\"iqHJy\", false, \"wuwhDEp\", \"0\"));" fullword ascii
    $s14 = "return feF;" fullword ascii
    $s15 = "print(WXofnWO);" fullword ascii
    $s16 = "var OoKyM = true;" fullword ascii
    $s17 = "var srXruV = false;" fullword ascii
    $s18 = "print (oSsb(\"034001025008\"));" fullword ascii
    $s19 = "var jnJqut = false;" fullword ascii
    $s20 = "var vkAhEms = false;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}