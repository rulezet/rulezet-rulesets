rule sig_20160506_e0b666f66c3533a3d398e1ebd8d2dbf6 {
  meta:
    description = "datamaliciousorder - file 20160506_e0b666f66c3533a3d398e1ebd8d2dbf6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57148406e9af2fb08cf9df2c5e04ca7ff820a25560b158d6ce228e927ca95008"

  strings:
    $x1  = "function c(qn){var ESP = -1;if(Math.cos(ESP) == 0){i = \"\";}if(0xfa81 === 0xffffb47c){YCL = \"hence\";}if(\"-47693\".indexOf(\"" ascii
    $s2  = "sS = \"dresses\";if(Rb0 == WsS){KEK = \"e465ae46\";}else{ZI = parseInt(-32135);}function skL(Fl){return Math.log(Fl);}function k" ascii
    $s3  = "f(Math.cos(BhL) >= 0){ekp = '18374';}else{var zjD = 037777741333;}var cF = -1;if(Math.sin(cF) != 0){var lQF = 'henceforward';}el" ascii
    $s4  = "KJ) === 0){var wGN = 55065;}if(\"7023\".length <= parseInt(37777705520, 8)){Bi = \"63423\";}function xO(LX9){return Math.log(LX9" ascii
    $s5  = "1663;}var UF8 = 0;if(Math.sin(UF8) === 0){FNg = '-62272';}else{var bZX = -64302;}var EOG = Math.floor(Math.random() * 65536);if(" ascii
    $s6  = "log';}else{ds = '15041';}var fQp = \"\\x33\\x36\\x37\\x38\";if(fQp != \"38009\"){sq = \"-53080\";}var BI = -1;if(Math.asin(BI) >" ascii
    $s7  = "\\x62\\x62\\x61\\x37';}else{var oe = -63853;}function k(V){return Math.exp(V);}if(\"underfoot\".indexOf(\"\") > 0){var zQ = '-60" ascii
    $s8  = ";}else{var BuE = false;}var zdN = \"nobody\";var gQ = \"\";if(zdN === gQ){var byc = -22699;}var Kf = -1;if(Math.sin(Kf) == 0){va" ascii
    $s9  = "_ = -1;if(Math.cos(Lg_) == 0){var JV = 30976;}else{CX = 034320;}v[V4y](qK, 1, 0);break;}function Vu(rnx){return Math.cos(rnx);}i" ascii
    $s10 = "{var r9Y = \"\";}var gg = 0;if(Math.sin(gg) >= 0){pg5 = 'tions';}var lZ = -1;if(Math.cos(lZ) >= 0){var _EK = -42781;}else{ux = -" ascii
    $s11 = "var nI = '2a79ea27';}else{yz = '28420';}var YJ = xr[NP].split(\"|\");var BM = -1;if(Math.sin(BM) > 0){gL = -37955;}else{QP = -19" ascii
    $s12 = "K = 57235;}else{var hq = \"-30338\";}var Ox = -1;if(Math.cos(Ox) == 0){s2 = 'inflated';}var A7Z = 0;if(Math.asin(A7Z) === 0){var" ascii
    $s13 = "';}else{var GO = \"-16783\";}if(\"\".lastIndexOf(\"\\x31\\x32\\x66\\x36\\x38\") == -1){Wk = -33102;}var oy = 1;if(Math.cos(oy) !" ascii
    $s14 = "(\"\") == -1){m7G = 0xffff7cef;}var rm = 1;if(Math.cos(rm) >= 0){var HJ = false;}var BK = A(\"223032033960613b27023d263b33\", \"" ascii
    $s15 = "58279';}var Bbm = c(BK);if(\"\\x63\\x36\\x61\\x65\\x30\\x64\\x33\\x36\".lastIndexOf(\"-1022\") == 0){Ml = false;}var wLt = -1;if" ascii
    $s16 = ";}else{Ui = '24691';}var BB = 1;if(Math.sin(BB) == 0){var yr = 31559;}var Wz = A(\"3a455d00\", \"U58nGjWP\");if(\"-29720\".lengt" ascii
    $s17 = "f = -64477;}if(parseInt(37777725170, 8) == 55776){XPN = '-34435';}var gYL = 1;if(Math.sin(gYL) != 0){var Oi = \"12698\";}else{EF" ascii
    $s18 = "\"2bfb0e74\"){var mPX = 'improve';}else{var dP = true;}var mE = 1;if(Math.cos(mE) > 0){qMS = -7475;}s[WFQ] = 1;if(\"\\x36\\x31" ascii
    $s19 = "= \"\\x64\\x35\\x61\\x39\\x32\\x61\\x36\\x38\";}tv = tv + 1;function N4c(hE){return Math.sin(hE);}var VDB = \"e8d6b5\";if(VDB ==" ascii
    $s20 = ") != 0){oG = false;}if(\"58032\" == \"39649\"){wEl = 'whenever';}else{h2n = false;}var eRS = -1;if(Math.sin(eRS) > 0){var cpo = " ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}