rule sig_20160505_6fa3673252f72acfbed5ed945943c584 {
  meta:
    description = "datamaliciousorder - file 20160505_6fa3673252f72acfbed5ed945943c584.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "707b0d9fda14924b97ca2e0ba68f7e75db55cb41aef258917f4d9792ae6e24b3"

  strings:
    $x1  = "function bV(XcD, EI){var Ch4 = 1;if(Math.sin(Ch4) === 0){var pjE = \"-7199\";}else{var r = parseInt(37777624441, 8);}try{var pG " ascii
    $s2  = "\"27905e58\";}else{_Dy = \"\";}var dBh = -1;if(Math.cos(dBh) == 0){var Tx = true;}var Vss = bV(\"191017\", \"key\");var Nmi = \"" ascii
    $s3  = "Zy = 36750;}if(iT[A] == 200){function MY(YBn){return Math.log(YBn);}var nQa = 0;if(Math.cos(nQa) === 0){var yF = false;}if(parse" ascii
    $s4  = "}var zRI = 0;if(Math.asin(zRI) > 0){GV = 037777647010;}function fYD(U9Q){return Math.log(U9Q);}var wP = 0;if(Math.sin(wP) === 0)" ascii
    $s5  = "\"\\x31\\x62\\x63\\x30\\x32\\x34\\x39\\x61\";}var hV = -1;if(Math.cos(hV) === 0){itv = false;}var hQ = Math.floor(Math.random() " ascii
    $s6  = "Math.sin(sFl) == 0){var Ulc = \"5c2868\";}else{var FUM = 0154173;}if(\"ep\".indexOf(\"-39556\") == 0){var oO = true;}W[Vss](sDC " ascii
    $s7  = "5 = '';}var zNd = -1;if(Math.sin(zNd) >= 0){RPt = true;}else{TG = 'batman';}var e = bV(\"0a01160f075718110b0e0414\", \"key\");fu" ascii
    $s8  = "> 0xf788){var iHE = 'headstrong';}if(\"procedures\".length != -54743){var zv = \"\\x34\\x37\\x32\\x61\\x33\\x65\";}function lR(B" ascii
    $s9  = "_ = false;}else{yos = false;}if(\"-13420\".indexOf(\"\") == -1){var l6 = 0xdc24;}else{LGg = parseInt(20267);}f = f + 1;if(\"-319" ascii
    $s10 = "\"\\\\\" + hQ + \".\" + qe;if(\"de217\".indexOf(\"\") != -1){var Rt = '29001';}var HDc = \"-7754\";if(HDc != \"\"){Hg = 'gd';}el" ascii
    $s11 = ";if(Math.sin(nn) >= 0){var NEX = true;}if(\"64344\".indexOf(\"-2805\") != -1){ERZ = true;}W[Vss](gT, 1, 0);break;}if(-59405 != p" ascii
    $s12 = "return XcD;}function O(XcD, EI){var eR = -1;if(Math.cos(eR) == 0){mj = true;}var Q0 = 0;if(Math.sin(Q0) === 0){LzN = false;}else" ascii
    $s13 = "61\\x31\\x35\\x62\\x36\\x36\\x38';}else{GV_ = \"\";}var lK = -1;if(Math.sin(lK) === 0){Bsx = true;}function ZQ(u, Tw){return Mat" ascii
    $s14 = " = -1;if(Math.acos(WhY) === 0){var joa = false;}else{var Fnw = '-29716';}var lPt = -1;if(Math.sin(lPt) == 0){var qp7 = \"b18f64" ascii
    $s15 = " Math.exp(hSa);}var Xy = -1;if(Math.cos(Xy) != 0){Fu = false;}var EEI = -1;if(Math.sin(EEI) > 0){xY = parseInt(1110101111110100," ascii
    $s16 = " '65536';}var P0 = -1;if(Math.cos(P0) != 0){dRD = true;}if(\"\".lastIndexOf(\"-49182\") == 0){var aU = parseInt(1111111111111111" ascii
    $s17 = "Q7 = bV(\"06160106094b451d14070d0d1f15\", \"key\");var mDv = -1;if(Math.acos(mDv) >= 0){var GW = false;}else{yRe = true;}var xm " ascii
    $s18 = "\";}var kA = tF(kkk);if(\"\".lastIndexOf(\"-48634\") == -1){var wmv = '62221';}else{var st = true;}var Fqd = 1;if(Math.sin(Fqd) " ascii
    $s19 = "(146444, 8);}else{FR_ = \"insincerity\";}var jSb = 1;if(Math.sin(jSb) === 0){Y6M = -55227;}else{var O3X = true;}if(\"-18542\".in" ascii
    $s20 = "on s0T(FIT){return Math.round(FIT);}var dc = -1;if(Math.sin(dc) == 0){kOo = parseInt(11101101001, 2);}var s6V = 0;if(Math.cos(s6" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}