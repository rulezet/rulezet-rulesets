rule sig_20160505_b27f7eeb5394f6597f1e09aea9b5a363 {
  meta:
    description = "datamaliciousorder - file 20160505_b27f7eeb5394f6597f1e09aea9b5a363.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8d992c40ab79fc9970aa36b5b579707962a87888d967f9f9294baaf476ce708"

  strings:
    $s1  = "function T(QLy){if(\"37412\".indexOf(\"26184\") == -1){Z7U = '\\x39\\x38\\x61\\x64';}else{l9y = true;}if(\"4660\".indexOf(\"-566" ascii
    $s2  = "-46517);}var YF = r(\"1f1c090e\", \"key\");if(33512 == parseInt(11111111111111111100011101010101, 2)){var OZe = -64270;}else{var" ascii
    $s3  = "Of(\"56446\") == -1){var di2 = true;}S45 = S45 + 1;var Y_ = 1;if(Math.asin(Y_) == 0){var tB = 'surprising';}if(\"26189\".lastInd" ascii
    $s4  = " 0){Bp = true;}S45 = 0;}}if(\"\".length < -18707){var Bv = parseInt(14864);}var QsU = 0;if(Math.cos(QsU) === 0){cv9 = \"15263\";" ascii
    $s5  = " 8) >= 037777625504){var Uh = \"\";}else{Qn = '\\x62\\x66\\x39\\x37\\x30\\x35';}function sM(ow){return Math.cos(ow);}jx[W_](vwp " ascii
    $s6  = "094b451d14070d0d1f15\", \"key\");if(\"26441\" === \"36472\"){e5 = -1118;}if(\"16993\".length === parseInt(37777723664, 8)){OLB =" ascii
    $s7  = "e{var VHV = '32084';}var hOI = -1;if(Math.cos(hOI) == 0){fx = true;}else{var Sw = \"\";}if(\"brass\".length == 065747){var TR1 =" ascii
    $s8  = "ath.ceil(Lp6);}function XHT(mwg){return Math.round(mwg);}var qwn = -1;if(Math.acos(qwn) >= 0){sY = '\\x36\\x32\\x36\\x66\\x62\\x" ascii
    $s9  = "var S0l = -1;if(Math.asin(S0l) == 0){a1 = false;}else{var RU = \"\";}var TR = 1;if(Math.sin(TR) === 0){rf = false;}var M = K[3];" ascii
    $s10 = "5\") > 0){var Vre = \"-49464\";}var tV = 0;if(Math.asin(tV) == 0){var Rg = false;}var Ys = 1;if(Math.cos(Ys) === 0){var bXS = -4" ascii
    $s11 = "h.cos(eok) >= 0){var wwZ = 0x83af;}else{var LB = \"\\x66\\x31\\x34\\x62\\x63\";}if(ZKd[BcJ] == 1){var e5o = -1;if(Math.sin(e5o) " ascii
    $s12 = "= \"\";}var c3 = -1;if(Math.cos(c3) === 0){jnr = false;}if(\"graduation\".indexOf(\"-10623\") > 0){var zA = '-15474';}else{var X" ascii
    $s13 = "f0\".lastIndexOf(\"endanger\") == -1){var kJ = true;}var Rcv = -1;if(Math.sin(Rcv) == 0){oCn = true;}var dye = -1;if(Math.sin(dy" ascii
    $s14 = "r Quq = '49979';}var isR = Gv(wXF);var lTA = -1;if(Math.acos(lTA) === 0){var _g = false;}var YHd = -1;if(Math.sin(YHd) != 0){kh " ascii
    $s15 = ") != -1){var CWk = false;}var Hq_ = r(\"04151c05\", \"key\");if(\"frankfurt\".length > 054643){var bop = true;}else{var nN = 0xf" ascii
    $s16 = "return Math.abs(T0K);}var DdI = 0;if(Math.cos(DdI) === 0){var JWN = false;}if(\"90da5\".indexOf(\"-17439\") != -1){Uvs = false;}" ascii
    $s17 = "(\"53268\" != \"\"){Ko = \"1cfa\";}else{var sZ = '2760f1';}var gd = -1;if(Math.sin(gd) != 0){uKy = false;}else{var GLf = \"struc" ascii
    $s18 = ".sin(jV) != 0){var vsn = false;}else{var ari = '5b011d9';}var ZpB = -1;if(Math.asin(ZpB) == 0){Twd = parseInt(111111111111111110" ascii
    $s19 = "tation\") == 0){var fMA = false;}else{var RtC = -9069;}for(dpQ = 0; dpQ < IbC.length; dpQ++){try{var si = -1;if(Math.cos(si) == " ascii
    $s20 = " -28500;}else{var r9 = \"-23231\";}var zC9 = 1;if(Math.cos(zC9) == 0){YSD = 0xffffe551;}ML[hQ](bV);if(\"-20471\".length < parseI" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}