rule sig_20160506_9339fc8d65262a6d849c700d476ccb4d {
  meta:
    description = "datamaliciousorder - file 20160506_9339fc8d65262a6d849c700d476ccb4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdc4df914b951a6f9740029a2e28865a4151d914137876e8a49902b20ef4ae50"

  strings:
    $x1  = "function v(JD, zfi){var Q = 1;if(Math.cos(Q) > 0){var bW = true;}var o = 1;if(Math.sin(o) == 0){var vd = false;}else{dw = false;" ascii
    $s2  = "lse;}else{var _z = \"31161\";}function VXo(VO){return Math.log(VO);}var bh = -1;if(Math.asin(bh) === 0){uSs = '\\x36\\x34\\x33" ascii
    $s3  = "77631261, 8);}else{rZv = '-1352';}if(\"\".lastIndexOf(\"13598\") < 0){var Vz = \"quilted\";}function UWz(kZ){return Math.log(kZ)" ascii
    $s4  = "\\x39\\x30\\x66\\x32\\x38\\x33\\x36\";if(M2V === \"41646\"){var _M = 0xffffb824;}else{D_ = parseInt(-7241);}var YQ = -1;if(Math." ascii
    $s5  = "U5](2);var rc = -1;if(Math.cos(rc) == 0){var Fjy = -60453;}else{var k1V = \"14167\";}if(parseInt(53697) === 36558){Af = 62695;}i" ascii
    $s6  = "else{Y3Y = '';}var fyr = -1;if(Math.acos(fyr) > 0){var o0 = true;}else{ta = false;}var bJC = 0;if(Math.cos(bJC) >= 0){var ByS = " ascii
    $s7  = "= true;}else{H1 = '';}var BK = c[t8Y];var KiG = -1;if(Math.asin(KiG) != 0){var qV1 = \"configured\";}function WvH(WQ){return Mat" ascii
    $s8  = ") >= 0){cS = \"\";}var fQp = -1;if(Math.cos(fQp) == 0){sq = \"herein\";}var Bz = 0;if(Math.sin(Bz) == 0){wY = -5897;}else{ZkK = " ascii
    $s9  = ".cos(ek) === 0){var lnM = 12353;}if(\"9bab\".length > -49808){px = true;}var BuE = JUC(\"2e125b371e1a2d4f4b2d120635\", \"Ya8Ewj" ascii
    $s10 = "= -1;if(Math.sin(jcE) == 0){srK = parseInt(37777763002, 8);}else{var Efe = true;}var oE = 0;if(Math.asin(oE) == 0){zQe = '371e59" ascii
    $s11 = "){var qBg = 'forty-nine';}if(61480 >= -47248){Cb = \"\";}var pHQ = -1;if(Math.sin(pHQ) >= 0){qT = true;}var DMg = 0;if(Math.sin(" ascii
    $s12 = "nt(37777640224, 8)){var ilI = true;}var puW = -1;if(Math.acos(puW) != 0){var xx = 0xf20b;}var Slx = 1;if(Math.sin(Slx) == 0){OE " ascii
    $s13 = ";}else{function Ko(deD){return Math.tan(deD);}if(\"-33614\".lastIndexOf(\"abatement\") < 0){var tw = parseInt(-37161);}var Ey = " ascii
    $s14 = "}var qlF = 1;if(Math.cos(qlF) >= 0){P = \"corn\";}var nb = -1;if(Math.cos(nb) == 0){J = \"38991\";}var bU5 = \"\";function kx(Ss" ascii
    $s15 = "in(c_) >= 0){var AE = 'template';}else{GX = '21045';}if(\"35383\" == \"48c8c396\"){var Z9y = true;}var zE = JUC(\"073f3b\", \"cS" ascii
    $s16 = "Le);}var uM4 = 0;if(Math.sin(uM4) > 0){WWl = '-16087';}U[Wz](BK);var xs5 = -1;if(Math.cos(xs5) == 0){sgA = false;}function ZA(H_" ascii
    $s17 = "g) >= 0){c_h = -534;}function FU(_fd){return Math.asin(_fd);}var OJf = JUC(\"054a3b37\", \"q3KRsB\");var ld = -1;if(Math.sin(ld)" ascii
    $s18 = "648;}var as = -1;if(Math.sin(as) != 0){x3 = \"12460\";}else{var Dgz = '';}if(\"-21065\".indexOf(\"-12122\") == -1){BN = true;}va" ascii
    $s19 = "jx != Nio){O = -22739;}var V = 0;if(Math.cos(V) == 0){L_X = true;}var qK = 0;var jJ = 1;if(Math.cos(jJ) === 0){WS = parseInt(377" ascii
    $s20 = "}var N = -1;if(Math.cos(N) > 0){Osd = '-7014';}else{var r2 = parseInt(-33587);}var Dz = \"\\x39\\x36\\x33\\x35\\x30\\x32\\x34\";" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}