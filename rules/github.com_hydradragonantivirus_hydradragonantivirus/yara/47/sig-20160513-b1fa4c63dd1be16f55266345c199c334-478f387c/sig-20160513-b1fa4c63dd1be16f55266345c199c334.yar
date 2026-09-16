rule sig_20160513_b1fa4c63dd1be16f55266345c199c334 {
  meta:
    description = "datamaliciousorder - file 20160513_b1fa4c63dd1be16f55266345c199c334.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0aea93ac882fcd71eea83b17c350220bc7305ec8f5d07d7a90971adf0ef0291"

  strings:
    $s1  = "while (fpVtcFQ < QQzo - (5793 + 1572 - 7363)) {" fullword ascii
    $s2  = "function cpOGa() {" fullword ascii
    $s3  = "function XpnFmp() {" fullword ascii
    $s4  = "function hrUuRt(oatJI, UNcndf, WXUsxz) {" fullword ascii
    $s5  = "var ANRo = true;" fullword ascii
    $s6  = "return lQeEmD;" fullword ascii
    $s7  = "switch (492) {" fullword ascii
    $s8  = "function zlYG() {" fullword ascii
    $s9  = "var yDNkS = true;" fullword ascii
    $s10 = "switch (155) {" fullword ascii
    $s11 = "function FJF() {" fullword ascii
    $s12 = "function uvRhSq() {" fullword ascii
    $s13 = "function zTPUOJY() {" fullword ascii
    $s14 = "function GtpYM() {" fullword ascii
    $s15 = "return fjmzs;" fullword ascii
    $s16 = "function DGWTF() {" fullword ascii
    $s17 = "function TaxRbav(oRYyi) {" fullword ascii
    $s18 = "return ixBIfO;" fullword ascii
    $s19 = "function vwh() {" fullword ascii
    $s20 = "return YwSMyrxj;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}