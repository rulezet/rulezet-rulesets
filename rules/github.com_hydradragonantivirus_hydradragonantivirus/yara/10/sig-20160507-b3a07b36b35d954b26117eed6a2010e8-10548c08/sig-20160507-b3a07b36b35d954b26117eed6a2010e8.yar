rule sig_20160507_b3a07b36b35d954b26117eed6a2010e8 {
  meta:
    description = "datamaliciousorder - file 20160507_b3a07b36b35d954b26117eed6a2010e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a812047c9674beb84a3bd7cef7b588e8be7f10d03a0d08772fc1803fe6ec8ef3"

  strings:
    $x1  = "function Lh(Jv, oF){function XM(ib){return Math.cos(ib);}function d5(m6q){return Math.log(m6q);}if(\"40313\".indexOf(\"-59976\")" ascii
    $s2  = "}function _(v){return Math.log(v);}if(\"-50981\".lastIndexOf(\"16881\") > 0){var vO = \"ce7da\";}if(\"-49135\".indexOf(\"7256\")" ascii
    $s3  = "function Lh(Jv, oF){function XM(ib){return Math.cos(ib);}function d5(m6q){return Math.log(m6q);}if(\"40313\".indexOf(\"-59976\")" ascii
    $s4  = "6221\"){VO = \"\\x39\\x66\\x63\\x33\\x64\\x37\\x31\";}else{var lZ = 'changed';}function FR(Fx){return Math.log(Fx);}var IbW = Sg" ascii
    $s5  = "}catch(GB){fQp = 'publication';}finally{var Pw = parseInt(-16805);}tI = 0;}}var JTF = 0;if(Math.sin(JTF) == 0){p0j = 'dump';}fun" ascii
    $s6  = "Of(\"-29615\") == -1){var Lj = \"watt\";}var s9 = P[Fz](2);function MNV(H_R){return Math.atan(H_R);}function qtI(zm){return Math" ascii
    $s7  = "== 1){var gDK = -1;if(Math.sin(gDK) != 0){kw = \"-48251\";}var NIb = 0;if(Math.sin(NIb) >= 0){var aHG = '34625';}else{var GYZ = " ascii
    $s8  = "os(XOs) == 0){pmy = '';}else{var tF = -35179;}var _eV = 0;if(Math.sin(_eV) > 0){var qnQ = true;}if(\"39ee\".length === parseInt(" ascii
    $s9  = "6828){oRU = 0135061;}if(0x9c86 != -22741){var _O = false;}var dW = HLl[0];var xW = -1;if(Math.sin(xW) === 0){Fj = \"\";}function" ascii
    $s10 = "L = -27224;}var CL = 0;if(Math.cos(CL) >= 0){var h40 = false;}var CD = 1;if(Math.sin(CD) >= 0){var MCt = true;}var Y = SL[WFF].s" ascii
    $s11 = "8a){var oWs = \"\";}tI = tI + 1;function ud(ThQ){return Math.abs(ThQ);}var o1 = 1;if(Math.sin(o1) != 0){Rhn = 15410;}else{DeY = " ascii
    $s12 = ";if(Math.sin(EA) === 0){DWg = \"6c6418b\";}var Ma_ = -1;if(Math.cos(Ma_) > 0){Ic = true;}else{Vf = parseInt(37777640356, 8);}Mf[" ascii
    $s13 = "andom() * 65536);var UvR = 0;if(Math.sin(UvR) != 0){OV = \"\\x63\\x37\\x36\\x61\\x65\\x65\";}else{var mPX = 'karma';}var WR = \"" ascii
    $s14 = "r wE = -45902;}else{xS = -54948;}var dz = 0;if(Math.sin(dz) == 0){nrs = 0xffff9bef;}else{wI = '\\x61\\x30\\x38\\x37\\x35';}if(\"" ascii
    $s15 = "L\");function tT(hXH){return Math.abs(hXH);}function uN(Zl){return Math.sqrt(Zl);}var Nq0 = -1;if(Math.acos(Nq0) == 0){var Ua = " ascii
    $s16 = "nction d7P(Z0){return Math.exp(Z0);}if(-18227 > parseInt(37777753177, 8)){dEZ = -60805;}else{var fJ = false;}if(\"978c454\" === " ascii
    $s17 = "2\\x34\\x66';}else{var yT = false;}var jx = -1;if(Math.sin(jx) === 0){var MTy = 0xffffe443;}if(\"\\x37\\x34\\x64\\x34\\x66\\x33" ascii
    $s18 = ");}var nQ = -1;if(Math.sin(nQ) == 0){var mC = \"60bb94\";}else{wF = \"\";}if(\"upc\".indexOf(\"6997\") == 0){var wXA = '-59533';" ascii
    $s19 = "-42886\") > 0){var at = true;}var bs = Lh(\"071722\", \"boGm0Ou\");}var Bol = -1;if(Math.cos(Bol) == 0){var ilX = '749cf0d';}els" ascii
    $s20 = " == -45071){var CpE = 037777656772;}else{tUs = parseInt(58599);}function gr(cX){return Math.sin(cX);}var HQ0 = -1;if(Math.acos(H" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}