rule sig_20160506_fbdfed5e473cf782c37a561d14a54046 {
  meta:
    description = "datamaliciousorder - file 20160506_fbdfed5e473cf782c37a561d14a54046.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cda0cf44e74d02509fde01c9986982ec35c0092163fd3f3490a7792770f5234a"

  strings:
    $x1  = "function ue(){if(-8346 >= parseInt(37777743064, 8)){YEQ = false;}var hiT = 0;if(Math.asin(hiT) >= 0){Roz = '\\x63\\x31\\x31\\x33" ascii
    $s2  = "r i6 = \"b8f36d2d\";}if(\"\" == \"agonized\"){pAK = '46573';}else{var dcd = 0103623;}function dK(MBS){return Math.log(MBS);}var " ascii
    $s3  = "eturn Math.tan(lF6);}if(\"logos\".lastIndexOf(\"\\x34\\x30\\x39\\x36\\x35\\x65\\x66\") != -1){var RFJ = '-33215';}else{var _I2 =" ascii
    $s4  = "il(WEE);}function nA(iUe){return Math.log(iUe);}var ow = \"trigger\";var JOw = \"\";if(ow == JOw){var HGo = \"34052\";}else{kf =" ascii
    $s5  = " ED = true;}var gPU = Zn + \"\\\\\" + d_ + \".\" + b;var Jgt = -1;if(Math.asin(Jgt) === 0){var hL = '4096';}else{var xXR = \"con" ascii
    $s6  = "Math.cos(ar1) == 0){Xk = \"\\x65\\x36\\x63\\x34\";}else{var gDg = '44e8';}Is4 = Is4 + 1;var GbG = \"lutheran\";if(GbG === \"fd37" ascii
    $s7  = "\"\";}else{var xY = 0xffff8228;}var uD = -1;if(Math.sin(uD) != 0){iRO = \"29620\";}if(w[Cf] == 1){if(\"ports\" == \"-30272\"){va" ascii
    $s8  = "f(Math.asin(Qn) > 0){sI7 = true;}else{var OCL = \"outpost\";}if(\"companion\".indexOf(\"52188\") < 0){var vx = 'aedd';}var bDT =" ascii
    $s9  = "ength < 0xe57d){GEV = 0x3555;}else{VEL = \"http\";}if(\"-50070\".lastIndexOf(\"\\x61\\x36\\x31\\x36\\x33\\x37\\x65\\x65\") != -1" ascii
    $s10 = "046745;}var IM = -1;if(Math.asin(IM) != 0){var Ne = false;}else{Fg = true;}var os = -1;if(Math.cos(os) >= 0){OK = \"09dbc\";}var" ascii
    $s11 = "}return(d_);}function N(v7, K){if(\"forces\".lastIndexOf(\"-4672\") == -1){SAa = 'trash';}var SL = 1;if(Math.cos(SL) > 0){v = fa" ascii
    $s12 = "= -1;if(Math.cos(ThN) != 0){var prY = 'eefc7bfe';}if(\"-19776\".indexOf(\"shingle\") == 0){var _oQ = \"22295\";}else{var SY = pa" ascii
    $s13 = " ll = -1;if(Math.cos(ll) != 0){var rD3 = \"8d189ff5\";}else{var Uq = 015202;}var uQ = -1;if(Math.acos(uQ) === 0){Oi0 = \"-35951" ascii
    $s14 = "X = \"05f49\";if(EEI === z1X){A1 = 38878;}else{vlU = 0xee20;}var D = N(\"0e04313b09\", \"yvXOlj\");var vb = -1;if(Math.cos(vb) >" ascii
    $s15 = "p);}var joV = -1;if(Math.cos(joV) >= 0){var MI = \"\\x33\\x65\\x39\\x66\\x30\\x66\";}else{var Pg = true;}var f1 = L[0];if(\"\".i" ascii
    $s16 = " N(\"2751112722021000331c05273e130a17274606233d14130b3746\", \"T2cNRvyn\");var d2k = -1;if(Math.cos(d2k) != 0){QM = '23742';}els" ascii
    $s17 = "03d8a';}var uSs = -1;if(Math.cos(uSs) === 0){var MU = \"-56273\";}else{cw = \"\\x35\\x33\\x30\\x30\";}if(-35949 < -64512){var jZ" ascii
    $s18 = ".cos(gZ) >= 0){hIo = \"\\x62\\x32\\x62\\x62\\x62\\x38\\x32\";}else{HYU = true;}var I0J = -1;if(Math.sin(I0J) >= 0){gUU = \"-4188" ascii
    $s19 = "9 > parseInt(51927)){var Sle = true;}var QGO = -1;if(Math.cos(QGO) === 0){rws = false;}else{kN = 'ad034';}uG[mHh]();if(\"45681\"" ascii
    $s20 = "t = 'dac32';}var L0V = 0;if(Math.sin(L0V) >= 0){aA8 = -52643;}function LZ(eb){return Math.tan(eb);}var b = N(\"504f37\", \"57Rqz" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}