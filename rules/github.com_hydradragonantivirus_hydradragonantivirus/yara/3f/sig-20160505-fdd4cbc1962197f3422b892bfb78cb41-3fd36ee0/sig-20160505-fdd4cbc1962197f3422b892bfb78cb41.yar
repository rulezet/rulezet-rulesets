rule sig_20160505_fdd4cbc1962197f3422b892bfb78cb41 {
  meta:
    description = "datamaliciousorder - file 20160505_fdd4cbc1962197f3422b892bfb78cb41.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f3a8ce69dcaf2bd295e6fd7e0b6bdba41b5238862f8477cd4d49d520a649446"

  strings:
    $s1  = "function Xd(E, _Q){var Ke = 0;if(Math.cos(Ke) != 0){var LY = \"\\x35\\x63\\x37\\x36\\x32\\x33\\x31\";}if(-20123 != parseInt(3777" ascii
    $s2  = "R = \"-23982\";}var Wn = Xd(\"18040f0e11160d0c150e\", \"key\");function uv(dQ){return Math.log(dQ);}if(\"sampling\".indexOf(\"51" ascii
    $s3  = "arseInt(-28453);}if(0xffff9bef > parseInt(-59702)){XG = '-535';}function Nr(xbq){return Math.log(xbq);}if(\"\\x33\\x34\\x61\\x31" ascii
    $s4  = "f075718110b0e0414\", \"key\");var DVF = -1;if(Math.cos(DVF) >= 0){var CYD = true;}if(\"-3864\".length === -39585){ad = \"\";}var" ascii
    $s5  = "}else{var wt = \"\";}var iO = -1;if(Math.acos(iO) === 0){ak = 0x851c;}if(a9D == Xd(\"263f\", \"key\")){var JJY = -1;if(Math.cos(" ascii
    $s6  = "= false;}if(parseInt(-1571) >= 0x2a00){Nzr = 'wit';}function tWM(VxK){return Math.abs(VxK);}var fZ = -1;if(Math.cos(fZ) >= 0){va" ascii
    $s7  = " = false;}var Ws = 1;if(Math.sin(Ws) == 0){rF = 0xffff10ef;}var wg = -1;if(Math.sin(wg) === 0){var mZc = '28278';}else{gE = '369" ascii
    $s8  = " = true;}var C = vE(w);var Zr7 = -1;if(Math.sin(Zr7) === 0){lgc = true;}var VCI = -1;if(Math.cos(VCI) >= 0){var eL = '15875';}if" ascii
    $s9  = "{var Gf0 = \"gp\";}var Pi = -1;if(Math.cos(Pi) === 0){var v9k = \"99ec64\";}else{var yyz = parseInt(1010011010000001, 2);}var yF" ascii
    $s10 = " Math.exp(FYZ);}var z_ = 1;if(Math.sin(z_) != 0){var My = \"-57105\";}var IYB = -1;if(Math.acos(IYB) >= 0){var Mt_ = false;}var " ascii
    $s11 = "lastIndexOf(\"-37231\") == -1){iW = '-13418';}function mvf(wJU){return Math.tan(wJU);}return(j);}function Ia(){var qtf = 1;if(Ma" ascii
    $s12 = "_ != lht){var St = true;}var Rw = -1;if(Math.sin(Rw) == 0){var rf = 0xffff00e8;}if(\"\\x34\\x37\\x63\\x65\\x30\".lastIndexOf(\"" ascii
    $s13 = "63\\x62\\x66\\x62';}else{var tr = true;}var yw = -1;if(Math.cos(yw) === 0){var x8B = \"16998\";}if(\"\\x31\\x39\\x31\\x63\\x36" ascii
    $s14 = ";}function Lh(rYe){return Math.tan(rYe);}if(0xffffd10a != 0xb07d){var xD = 'bmw';}if(\"53952\".indexOf(\"9917c\") != -1){vuF = p" ascii
    $s15 = "7031607011c19\", \"key\");var NR = 0;if(Math.acos(NR) === 0){Uc = \"\";}else{var z5b = '518d52ee';}var Bkl = -1;if(Math.acos(Bkl" ascii
    $s16 = "{var fQp = true;}var HwZ = -1;if(Math.asin(HwZ) === 0){ws = '\\x61\\x32\\x35\\x61\\x36\\x63';}var vuI = 1;if(Math.cos(vuI) >= 0)" ascii
    $s17 = "8\";}var vR = 1;if(Math.acos(vR) === 0){Qj = true;}if(\"c20bb2\".length != -54114){oi = '55246';}else{jb = \"12002\";}if(\"flora" ascii
    $s18 = "nction Gxh(lt){return Math.tan(lt);}function uX8(AKp){return Math.floor(AKp);}var AQ = lZ + \"\\\\\" + z__ + \".\" + U;if(\"d3f9" ascii
    $s19 = ";}function SJ(EJ){return Math.abs(EJ);}var PTh = -1;if(Math.sin(PTh) >= 0){var L0c = \"\\x34\\x32\\x64\\x30\\x32\\x62\\x64\\x30" ascii
    $s20 = "x31\\x33\\x39\\x61\") == -1){zQX = false;}if(parseInt(37777775700, 8) != 0xf22c){var aFY = true;}continue;}var fkp = 0;if(Math.c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}