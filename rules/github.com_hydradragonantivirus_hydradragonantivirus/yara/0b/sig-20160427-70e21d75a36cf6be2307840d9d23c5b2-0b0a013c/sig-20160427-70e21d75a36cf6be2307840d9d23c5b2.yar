rule sig_20160427_70e21d75a36cf6be2307840d9d23c5b2 {
  meta:
    description = "datamaliciousorder - file 20160427_70e21d75a36cf6be2307840d9d23c5b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40bc1ffa4cb1aac60317e6018bd9435b1f83105b60c8e799a51be115cda695b6"

  strings:
    $s1  = " var riME = 7838;var DqPn = 2319;var Grsj = 5280;riME = DqPn * Grsj;var wePZu = 5817;wePZu = 8854 - 1906;var fCkbiG = 3609;var T" ascii
    $s2  = "bcaGV = 1604;var dOzP = 6411;fCkbiG = TbcaGV - dOzP;riME = 7943 + 4446;" fullword ascii
    $s3  = " var riME = 7838;var DqPn = 2319;var Grsj = 5280;riME = DqPn * Grsj;var wePZu = 5817;wePZu = 8854 - 1906;var fCkbiG = 3609;var T" ascii
    $s4  = "}switch(4) {" fullword ascii
    $s5  = " if(5 == false) {" fullword ascii
    $s6  = " if(4 == false) {" fullword ascii
    $s7  = " if(7 == false) {" fullword ascii
    $s8  = " if(4 === false) {" fullword ascii
    $s9  = " if(2 === true) {" fullword ascii
    $s10 = "}function mTPeCB (pkt,LWdt,vsAhE) {" fullword ascii
    $s11 = "function sPi (MMAGL) {" fullword ascii
    $s12 = "  var oMdbXm = true; " fullword ascii
    $s13 = "} var azXIsWO = true; " fullword ascii
    $s14 = "  var fxMErh = false; " fullword ascii
    $s15 = "function mQH () {" fullword ascii
    $s16 = "}switch(KpZofb) {" fullword ascii
    $s17 = " if(xBUPB == false) {" fullword ascii
    $s18 = " var hgVWmG = false; " fullword ascii
    $s19 = "  var HgMex = true; " fullword ascii
    $s20 = " var CWlkY = false; " fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}