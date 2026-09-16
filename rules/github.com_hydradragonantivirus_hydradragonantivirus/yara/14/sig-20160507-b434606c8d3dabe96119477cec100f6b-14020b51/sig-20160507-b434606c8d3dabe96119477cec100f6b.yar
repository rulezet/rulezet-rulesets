rule sig_20160507_b434606c8d3dabe96119477cec100f6b {
  meta:
    description = "datamaliciousorder - file 20160507_b434606c8d3dabe96119477cec100f6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee37ec59539e7b3cfd9929f72099b04a6362a1f1588ac9406408873db92b6428"

  strings:
    $s1  = "function kXA(Z, gq){var m = 1;if(Math.cos(m) != 0){var QED = parseInt(37777612244, 8);}var Dv = \"43571\";if(Dv === \"901db33\")" ascii
    $s2  = "){return Math.log(uSs);}function dO(IB){return Math.floor(IB);}function oCl(CH_){return Math.asin(CH_);}var vi = 1;if(Math.sin(v" ascii
    $s3  = "777676560;}if(\"\".length <= 42379){HPS = 0xffff67b7;}else{Sa = \"\\x34\\x63\\x35\\x36\\x33\\x39\\x32\";}function re(ZZF){return" ascii
    $s4  = "ion _q(KR){return Math.cos(KR);}var ssh = \"usage\";var rK = \"\";if(ssh != rK){var WPK = \"mud\";}if(\"-10594\".indexOf(\"-5785" ascii
    $s5  = "turn Math.log(vb);}WZ[ICa] = 1;}}}catch(Az){if(\"\".length === 0xb1e3){var WWo = \"\\x37\\x37\\x37\\x37\\x32\";}var xG = \"d6dc" ascii
    $s6  = ";}else{TO = parseInt(36847);}function Pu(Hfc){return Math.log(Hfc);}if(\"3cab3\".length >= 0xffff9803){Ca_ = false;}else{Hz6 = '" ascii
    $s7  = "an(u8x);}if(\"\".length <= 024652){var DVF = '-36851';}else{jo = '';}var UGH = -1;if(Math.cos(UGH) > 0){ch = -61469;}else{var g_" ascii
    $s8  = "gth == 0161616){dG = '16352';}var fV = 1;if(Math.sin(fV) == 0){CTV = false;}var aFF = Erf[Ub].split(\"|\");var zC9 = -1;if(Math." ascii
    $s9  = "x66\\x38\") == 0){GrX = parseInt(37777744063, 8);}else{GQ = \"28fda\";}var Ekk = -1;if(Math.cos(Ekk) > 0){var nbd = true;}return" ascii
    $s10 = "iw){return Math.exp(Aiw);}var qT = P(\"375e2b3f12\", \"T2DLw0\");var dhK = -1;if(Math.sin(dhK) != 0){ee = true;}else{M8z = 0xfff" ascii
    $s11 = "= true;}var OeB = new ActiveXObject(C);var sJ = -1;if(Math.acos(sJ) >= 0){var uD = \"forked\";}var BhL = 1;if(Math.cos(BhL) >= 0" ascii
    $s12 = "M = \"full\";if(oY == QM){kTo = true;}var eQy = 0;if(Math.cos(eQy) == 0){var lGl = '';}else{var ZUP = false;}var rI = -1;if(Math" ascii
    $s13 = "if(Math.sin(EM9) === 0){MbV = \"bd92d1b8\";}else{var UWr = '-1300';}var wOY = Math.floor(Math.random() * 65536);if(-3790 != 0xff" ascii
    $s14 = "alse;}if(\"38ccd\".length === -33436){_3 = true;}else{var Th = \"guano\";}var fe = 0;if(Math.cos(fe) == 0){var DNJ = false;}var " ascii
    $s15 = "r ilK = -27541;}var Fg = 1;if(Math.sin(Fg) === 0){var DD = '8d98ea3';}else{TTk = '-30592';}if(EIE >= Tt.length){if(\"-49961\".le" ascii
    $s16 = "th > -47390){GzO = true;}else{nAb = '-15456';}var BS = -1;if(Math.cos(BS) >= 0){_cE = '-39813';}else{v_Z = false;}if(parseInt(10" ascii
    $s17 = "J = 0x36af;}var fQW = 1;if(Math.cos(fQW) > 0){QaA = false;}var FQ = P(\"132842085d20030439540046\", \"aM1x2Np\");var wDr = -1;if" ascii
    $s18 = " \"\";}var FAp = -1;if(Math.cos(FAp) > 0){var V8 = true;}var zR = -1;if(Math.sin(zR) >= 0){var ufP = 0xffffbf54;}else{R = 0xffff" ascii
    $s19 = "ffff5a76 === -64246){var wmv = '-44940';}var Fqd = -1;if(Math.cos(Fqd) != 0){var sod = false;}else{var Eq = '-14652';}if(\"21113" ascii
    $s20 = " vT(){var _6 = -1;if(Math.asin(_6) >= 0){PB = '3e00cf7';}else{var _T = 34026;}var Xy = 0;if(Math.sin(Xy) === 0){var wmw = 047643" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}