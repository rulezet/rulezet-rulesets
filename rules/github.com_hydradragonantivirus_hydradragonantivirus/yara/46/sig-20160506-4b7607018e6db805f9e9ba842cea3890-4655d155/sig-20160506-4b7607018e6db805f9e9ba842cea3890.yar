rule sig_20160506_4b7607018e6db805f9e9ba842cea3890 {
  meta:
    description = "datamaliciousorder - file 20160506_4b7607018e6db805f9e9ba842cea3890.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83b3e2cc55685856f3a958c4fe63979d5da28a7babf86e8aee5910cfdd9d4311"

  strings:
    $s1  = "function H(aR){var V7p = 0;if(Math.sin(V7p) === 0){xP = \"\\x66\\x36\\x36\\x62\\x31\\x62\";}else{var nSw = '32842e5d';}var ENq =" ascii
    $s2  = " = \"\";}qf[o_j] = 1;function aA8(SYm){return Math.log(SYm);}if(-63368 === 24583){var nc = -26478;}if(4344 === 0xffff6047){zK = " ascii
    $s3  = "03018587b100a3e59502c1412624e49650d5e\", \"qnSw5T\");function wk(wEc){return Math.log(wEc);}var dye = -1;if(Math.acos(dye) >= 0)" ascii
    $s4  = "+ \".\" + QI;var QY = -1;if(Math.sin(QY) > 0){var Kmn = false;}var lo = 0;if(Math.asin(lo) >= 0){var qhS = true;}else{var kpD = " ascii
    $s5  = "{return Math.floor(jd);}if(\"ff1ced\" != \"flattened\"){dEr = -53978;}var pHn = o1[dw].split(\"|\");if(\"anthropology\" === \"\"" ascii
    $s6  = "2561e23';}else{var oK = 'post';}if(\"\\x63\\x66\\x36\\x38\\x35\\x62\\x36\".indexOf(\"\\x39\\x33\\x33\\x38\\x65\") == -1){HJ = tr" ascii
    $s7  = "r Zbz = 0;if(Math.asin(Zbz) != 0){GPd = true;}function Ws(Ab){return Math.cos(Ab);}var RK = -1;if(Math.cos(RK) === 0){VEL = \"\"" ascii
    $s8  = "alse;}else{var bJq = \"\\x37\\x33\\x36\\x36\\x62\";}var Edc = -1;if(Math.sin(Edc) != 0){var Pz = '-35831';}else{var uxM = \"1688" ascii
    $s9  = " -1;if(Math.acos(Inz) == 0){Qj = false;}else{var pjM = \"\\x65\\x61\\x63\\x63\\x62\";}var TNz = 0;if(Math.cos(TNz) > 0){Ks = \"" ascii
    $s10 = "(Vpr);var Pmq = -1;if(Math.sin(Pmq) === 0){WsS = 0xffff1f30;}else{Ekn = \"37052\";}var ZI = 0;if(Math.asin(ZI) === 0){var mvB = " ascii
    $s11 = " true;}var bON = -1;if(Math.sin(bON) != 0){Mxl = '\\x61\\x62\\x30\\x30\\x32\\x62\\x64';}if(\"b91c\".lastIndexOf(\"languages\") >" ascii
    $s12 = "-24858\".indexOf(\"\") > 0){Ku5 = \"-18830\";}var UJ = -1;if(Math.cos(UJ) >= 0){var zu = '\\x37\\x34\\x33\\x63\\x31\\x31';}else{" ascii
    $s13 = "x31\\x65\";}else{HYU = true;}var I0J = -1;if(Math.cos(I0J) > 0){gUU = \"19314\";}else{KQ = 0x1344;}var aR = H(Igu);if(\"\".lastI" ascii
    $s14 = "n = \"cancelled\";}var gzJ = -1;if(Math.cos(gzJ) != 0){uB = true;}function zmC(XUT){return Math.sin(XUT);}var Kr = Wi + \"\\\\\"" ascii
    $s15 = "r QI = NL(\"0f082a\", \"kdFzsC3\");}else{var Wn = 1;if(Math.cos(Wn) === 0){var TC = true;}var Vx = -1;if(Math.asin(Vx) > 0){var " ascii
    $s16 = ", 8);}var vj = NL(\"1a03470d3e1c11000e54\", \"ib1hJsw\");var DlX = -1;if(Math.sin(DlX) != 0){var V5p = 2602;}else{var R2 = \"2b3" ascii
    $s17 = " = false;}else{bq = -19691;}var T = NL(\"540b33383446604115273d2c003e\", \"9xKUXtN\");var XLj = -1;if(Math.sin(XLj) == 0){var Fr" ascii
    $s18 = "0c7\");}var PM = -1;if(Math.asin(PM) > 0){vq_ = parseInt(37777757463, 8);}else{C8 = \"c57d4c50\";}var Yo = 1;if(Math.cos(Yo) > 0" ascii
    $s19 = ");}return(xsI);}function NL(Igu, YH){var sd = -1;if(Math.cos(sd) > 0){var ad = 'nbc';}if(\"\".indexOf(\"\\x35\\x65\\x32\\x31\\x3" ascii
    $s20 = "\";}var uhZ = -1;if(Math.sin(uhZ) >= 0){var kd = '';}else{var Osd = \"-32492\";}var lnM = 1;if(Math.sin(lnM) === 0){Ctj = false;" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}