rule sig_20160505_6e282569c5856343f4115bebf5384159 {
  meta:
    description = "datamaliciousorder - file 20160505_6e282569c5856343f4115bebf5384159.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aad78b315fc5d2bc9499835b19fa55e81f17eb79206e6bd654a871d7c648f6e7"

  strings:
    $x1  = "function YeQ(ca9, l){var aGV = 1;if(Math.acos(aGV) === 0){S = \"criticized\";}if(\"coiffure\".lastIndexOf(\"unchanging\") == -1)" ascii
    $s2  = "\"tracker\";}if(\"\".lastIndexOf(\"-53421\") == -1){var aHG = 'flare';}else{var GYZ = false;}function OL(ryp){return Math.log(ry" ascii
    $s3  = "nction oY(QM){return Math.log(QM);}if(\"-36258\".lastIndexOf(\"9773\") == 0){bU = false;}if(\"c1285\".indexOf(\"\") != -1){tUs =" ascii
    $s4  = "x32\\x63\\x61\\x33';}function lkB(Alu){return Math.log(Alu);}var RPG = yrC(\"18040f0e11160d0c150e\", \"key\");if(0xffff212e < pa" ascii
    $s5  = " Math.cos(khQ);}hXH[Y]();function rJ(ZQ){return Math.log(ZQ);}var Cp0 = 0;if(Math.asin(Cp0) == 0){var LRL = true;}else{var GKX =" ascii
    $s6  = "n Math.log(W7);}var YY = \"10ce\";var qz = \"\";if(YY === qz){lt = '';}else{Ouj = \"\";}var cNg = 1;if(Math.cos(cNg) >= 0){QLO =" ascii
    $s7  = "= -1;if(Math.sin(lWV) > 0){var V7B = \"-15498\";}else{var hI = 0xffffea32;}var E = Math.floor(Math.random() * 65536);var iK = -1" ascii
    $s8  = "ar ew = \"58d2\";}var QRd = -1;if(Math.cos(QRd) != 0){var RY = false;}var gW = yrC(\"0f0915\", \"key\");}else{var GrX = 1;if(Mat" ascii
    $s9  = "f(Math.cos(iK) >= 0){var Dd = 0x7a1f;}else{kyF = parseInt(11111111111111110011000001011010, 2);}var TS = -1;if(Math.acos(TS) > 0" ascii
    $s10 = "seInt(11111111111111111110100001001001, 2);}function xRJ(IK){return Math.tan(IK);}var uPS = 0;if(\"truncheon\".length < 03777776" ascii
    $s11 = "ion ASp(NZv){return Math.sqrt(NZv);}var r = yrC(\"1811181f100a\", \"key\");var Sps = -1;if(Math.acos(Sps) === 0){sxX = parseInt(" ascii
    $s12 = "11111111111110010011110100, 2);}var dp = -1;if(Math.acos(dp) === 0){kLb = 'waive';}else{SXz = true;}var Vz = -1;if(Math.sin(Vz) " ascii
    $s13 = " = A1W();var NAu = -1;if(Math.sin(NAu) > 0){var NJz = 'columns';}var Lt = \"-26533\";var te = \"22628\";if(Lt === te){ug = false" ascii
    $s14 = "Int(1010110101001010, 2);}var Oi = -1;if(Math.cos(Oi) != 0){zK = false;}if(\"flier\" === \"acquittal\"){var Jkr = 50235;}else{va" ascii
    $s15 = "4360, 8)){Gzy = 'cc823b';}else{_Y7 = true;}var ms0 = -1;if(Math.sin(ms0) == 0){ZVX = \"49d86\";}else{DO = parseInt(1111110111001" ascii
    $s16 = "(Ax) >= 0){_s = false;}else{var CS = \"\";}function sr(yt){return Math.tan(yt);}var d1 = -1;if(Math.asin(d1) >= 0){hcZ = '\\x38" ascii
    $s17 = " 1, 0);break;}var pU = -1;if(Math.asin(pU) >= 0){var Ht = 58252;}else{var gDK = '-24913';}function Rv(cpv){return Math.tan(cpv);" ascii
    $s18 = "r wEc = XI(wk);var rD = -1;if(Math.sin(rD) === 0){var o_W = \"-44034\";}else{zhD = \"92d79ee9\";}if(\"\".indexOf(\"\") > 0){var " ascii
    $s19 = "34\\x64\\x65\".indexOf(\"\") == -1){rXe = '\\x39\\x63\\x65\\x61\\x31\\x30';}var vTM = -1;if(Math.cos(vTM) >= 0){var t1 = '36c30'" ascii
    $s20 = " sc8 = false;}if(\"\\x34\\x36\\x61\\x62\\x61\\x64\\x35\\x31\".lastIndexOf(\"25967\") < 0){nI = \"25275\";}var A8 = -1;if(Math.si" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}