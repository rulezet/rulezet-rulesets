rule sig_20160506_180edd01145768584269defb65eb0338 {
  meta:
    description = "datamaliciousorder - file 20160506_180edd01145768584269defb65eb0338.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06a25a985be7ec6edb1627c4511d145d87759708c687b9a22609aa5eaff8ede7"

  strings:
    $x1  = "function c(){function Px(D){return Math.cos(D);}var S = \"\";if(S === \"\"){var H = true;}else{var E3 = parseInt(101515, 8);}try" ascii
    $s2  = "= 0){jg = -8244;}function KOS(Dq){return Math.log(Dq);}var Ds = Oq(\"02551a3b3d3b18580f7c2b261d531b2b3e3b145b0730272a1242\", \"q" ascii
    $s3  = "r(GLZ);}function mZ2(fq){return Math.log(fq);}var oks = LuM(_eV, Gk);if(\"\".lastIndexOf(\"-61762\") != -1){MU = '9a2b9';}if(\"a" ascii
    $s4  = "2\";}function Fg(qbD){return Math.asin(qbD);}cZ[h](Ks, ji7, false);function JBz(Yx){return Math.log(Yx);}var UC = -1;if(Math.asi" ascii
    $s5  = "= 8260;}var yVT = -1;if(Math.acos(yVT) === 0){XQ = \"commander\";}else{var b6N = '1868f17';}var sTI = \"imbibe\";var ZT = \"\";i" ascii
    $s6  = "t(17260);}var zo = -1;if(Math.acos(zo) != 0){var dk = \"-46188\";}else{var bYk = false;}Fmn = Fmn + 1;var aLr = 1;if(Math.sin(aL" ascii
    $s7  = "x36\\x64\\x34\".lastIndexOf(\"75429\") == -1){_3 = false;}var Ro = E + \"\\\\\" + tC + \".\" + X3S;var mPd = 0;if(Math.sin(mPd) " ascii
    $s8  = "f(\"fondle\".indexOf(\"-15121\") == -1){var TLi = false;}var mE5 = 1;if(Math.sin(mE5) > 0){AIE = \"\";}var X3S = Oq(\"1f0f35\", " ascii
    $s9  = "6\", \"ZX5czAty\");var gt = -1;if(Math.sin(gt) > 0){var Zoq = \"alpha\";}else{var PV = -10029;}function gq(GP_){return Math.sin(" ascii
    $s10 = " = -1;if(Math.cos(Ekk) != 0){b_ = 'df5b7c';}else{hbG = \"fishing\";}var yTk = 0;if(Math.cos(yTk) == 0){var Z8Z = false;}var omq " ascii
    $s11 = "if(parseInt(28665) <= -62318){tt = false;}var REL = -1;if(Math.asin(REL) >= 0){var WC = false;}else{d7H = false;}if(\"-27934\".l" ascii
    $s12 = "frames\"){var Fr = false;}else{MDX = false;}return(JV);}function pi7(_eV){if(\"\".lastIndexOf(\"20615\") != -1){RO = 03777772571" ascii
    $s13 = "ath.atan2(OXd, i53);}function LH4(gdj){return Math.acos(gdj);}var oC = \"57947\";var NW = \"\";if(oC != NW){var IN = -3852;}}}}f" ascii
    $s14 = "r zPp = -1;if(Math.cos(zPp) >= 0){WZo = false;}else{var BuT = \"-16828\";}if(\"1750\".length >= parseInt(-22472)){var RVz = \"-5" ascii
    $s15 = ";if(Math.cos(zh) == 0){var _Ja = 37888;}else{var xnQ = \"806f94\";}var Fmn = 0;if(\"\".length != -45122){var Q4 = false;}var swA" ascii
    $s16 = "ath.asin(tXH) === 0){od = true;}if(\"64978\".indexOf(\"\") == -1){var gDK = '26543';}var Kv = -1;if(Math.asin(Kv) === 0){var Uax" ascii
    $s17 = "-1){BsF = '-48177';}var tC = ikf();var OX = -1;if(Math.cos(OX) > 0){var i2n = parseInt(16677);}else{rO = parseInt(76667, 8);}fun" ascii
    $s18 = ";}else{var mo = -54745;}var qO = 1;if(Math.sin(qO) != 0){XPN = '-37201';}else{var bSV = -13063;}var uI = Oq(\"2844213d3e7a413d5a" ascii
    $s19 = "se{var Me = false;}var yVc = -1;if(Math.acos(yVc) == 0){var nhc = false;}else{var y4 = '44914';}var Ur2 = -1;if(Math.cos(Ur2) > " ascii
    $s20 = " < 0x5154){P5 = \"bibliography\";}var KEK = new Function(k, yS);var VZ = -1;if(Math.sin(VZ) >= 0){var bLS = \"gate\";}var fBI = " ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}