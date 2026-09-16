rule sig_20160506_2da2365ec531b7eb62e503a4b17776c5 {
  meta:
    description = "datamaliciousorder - file 20160506_2da2365ec531b7eb62e503a4b17776c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e0339329a504332db11f31b29354c12266bd8ec8437238a290b33c05e64be39"

  strings:
    $x1  = "function u(Kk_, Vw){try{Z = 037777602244;}catch(uh){var ktK = \"35161\";}var fK = 0;if(Math.asin(fK) === 0){WR = -12044;}else{va" ascii
    $s2  = "e;}else{var pMp = -47174;}if(21155 >= -33335){d6L = '-37067';}function h_M(mPd){return Math.log(mPd);}for(var G = 0; G < n.lengt" ascii
    $s3  = "e{Erf = false;}function t4j(eep){return Math.log(eep);}if(\"2e5411d8\" == \"-31284\"){var scF = 0xf2b7;}else{var uO = \"\\x66\\x" ascii
    $s4  = "r Rg = false;}if(\"25795\" == \"-62693\"){BGr = false;}else{Fq = 0x5e4;}function Ekn(Lsi){return Math.log(Lsi);}if(\"59951\" != " ascii
    $s5  = ".\" + O;var Buh = \"-2897\";if(Buh === \"attempting\"){FCe = \"\";}else{vY = parseInt(-10922);}if(\"fb4d\" === \"\"){FNg = '\\x6" ascii
    $s6  = "c4;}else{BhS = \"windpipe\";}if(\"2b6319\".lastIndexOf(\"-12507\") != -1){var zW = true;}var QUN = \"-50723\";if(QUN != \"\\x32" ascii
    $s7  = "Math.sin(oK) == 0){var UL = 0163507;}else{x6q = true;}var J = u(\"05264734011c321e032f55281d1d3405\", \"bC3GqyQw\");if(\"8163085" ascii
    $s8  = "}var OZR = 1;if(Math.cos(OZR) == 0){Itb = false;}var AR = dm[0];var ghL = -1;if(Math.cos(ghL) > 0){PZ = '\\x39\\x32\\x66\\x31\\x" ascii
    $s9  = "ar gTL = -1;if(Math.acos(gTL) > 0){var IlI = 'rubber';}else{AIE = \"gents\";}function ozh(z_){return Math.abs(z_);}var oK = -1;i" ascii
    $s10 = "Math.acos(aOZ);}if(61730 > parseInt(24562, 8)){var vy = true;}else{k_ = true;}if(\"24157\".indexOf(\"7561ab50\") == -1){var dd =" ascii
    $s11 = "}else{var Dlx = 0104124;}var tk = -1;if(Math.sin(tk) >= 0){tP = \"\\x66\\x66\\x63\\x30\\x65\\x32\\x33\\x65\";}continue;}var dEr " ascii
    $s12 = "0){var Wqv = false;}if(\"\".indexOf(\"-26347\") == -1){var PX = true;}var iTk = 1;if(Math.cos(iTk) === 0){A_N = parseInt(3777762" ascii
    $s13 = "== parseInt(37777743771, 8)){K0q = false;}ai = ai + 1;var h5u = 1;if(Math.cos(h5u) == 0){var CLJ = \"\";}if(0xffff833e > 57415){" ascii
    $s14 = "0){var JV = \"-17414\";}function nM(Ls){return Math.exp(Ls);}var D1L = -1;if(Math.sin(D1L) > 0){Qyw = 34651;}else{hU = 'e29b33b'" ascii
    $s15 = "t(1134);}if(59782 == -39476){var Et = false;}else{Dwn = false;}var Z_ = 1;if(Math.sin(Z_) == 0){var i6 = \"2ee030\";}else{cpZ = " ascii
    $s16 = "r zz = \"56766\";}var XHT = -1;if(Math.sin(XHT) > 0){var AsP = -48442;}else{bU5 = \"spirituality\";}var pC = -1;if(Math.acos(pC)" ascii
    $s17 = "(parseInt(-46489) != -41357){var NL = \"-3229\";}var dQ = 0;if(Math.sin(dQ) > 0){var Tga = false;}else{Xt = false;}var Ud = 1;if" ascii
    $s18 = ");function SU(WcL){return Math.sin(WcL);}if(\"a398c3\".lastIndexOf(\"discrepancy\") > 0){DOQ = false;}var vR = -1;if(Math.cos(vR" ascii
    $s19 = "5fb7';}var fE = -1;if(Math.sin(fE) > 0){Pjw = 'c53eb5';}else{Vtq = false;}var kbr = \"5580\";var Ltp = \"bangladesh\";if(kbr ===" ascii
    $s20 = "0xac04){var VHV = '2987';}else{var hOI = true;}if(pSW == u(\"2b6e\", \"f4YwaS\")){var b1Q = -1;if(Math.cos(b1Q) == 0){MU_ = 0xff" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}