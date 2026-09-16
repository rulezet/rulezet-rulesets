rule sig_20160506_f2c7444920db00080f63f4e163530539 {
  meta:
    description = "datamaliciousorder - file 20160506_f2c7444920db00080f63f4e163530539.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f7e4f3706607271da73cc81dd6586483535f41060ab269ca56757ac599bc30d"

  strings:
    $s1  = "function aa(BU, G){var _ = 1;if(Math.acos(_) > 0){var c = \"\\x34\\x65\\x35\\x35\";}else{var N = false;}if(\"\".lastIndexOf(\"60" ascii
    $s2  = "lse{fb = -24972;}var K = v7 + \"\\\\\" + IK + \".\" + Fq;function Xp(Pj){return Math.cos(Pj);}if(\"oregon\".indexOf(\"56208\") =" ascii
    $s3  = "var Q_O = \"\";}else{var bLx = 12804;}var hf = 1;if(Math.sin(hf) === 0){GWA = \"portmanteau\";}if(\"e4828\".lastIndexOf(\"-37791" ascii
    $s4  = ".cos(iKb) >= 0){HIh = -20381;}else{var gR = false;}var C_ = 0;if(Math.asin(C_) != 0){var R4L = \"commentator\";}b[eBV](VyV);if(" ascii
    $s5  = "_t = -1;if(Math.asin(F_t) == 0){KO = 'billet';}else{var xM = 52125;}var jIF = 1;if(Math.sin(jIF) >= 0){hp0 = '\\x63\\x61\\x37\\x" ascii
    $s6  = "6, 8);}else{ogl = \"26737\";}var IFG = -1;if(Math.sin(IFG) >= 0){var jq = true;}else{var RF = 037777642100;}if(\"\".indexOf(\"\"" ascii
    $s7  = "}var UvR = -1;if(Math.sin(UvR) != 0){var O9a = true;}else{var BLC = '20257';}if(\"07b6bea\".length <= -21452){var zW5 = true;}el" ascii
    $s8  = "var z = -1;if(Math.sin(z) === 0){var QR = \"\\x38\\x33\\x65\\x38\\x65\\x66\\x35\";}return(y9);}function y4N(){if(\"\".length < p" ascii
    $s9  = "y = -1;if(Math.acos(wy) >= 0){PD1 = false;}function nVp(l6){return Math.sin(l6);}function PE(Vpr){return Math.atan(Vpr);}var ar1" ascii
    $s10 = "z = '3fb0485e';}else{var Vv = 037777762721;}var YC = -1;if(Math.sin(YC) != 0){pS = 0xffff520c;}if(\"\".length != parseInt(51988)" ascii
    $s11 = "{eMU = 067642;}finally{var du = true;}function _Un(M9){return Math.exp(M9);}var W = y[1];var Hag = -1;if(Math.acos(Hag) === 0){v" ascii
    $s12 = "else{Ys = '34410';}if(\"\\x31\\x31\\x34\\x31\\x39\\x33\".indexOf(\"\\x33\\x34\\x34\\x37\") < 0){oRU = -50400;}var uJ = 1;if(Math" ascii
    $s13 = "alse;}else{zJn = true;}var sPM = -1;if(Math.cos(sPM) === 0){gMW = -51667;}var U0j = 0;if(Math.cos(U0j) >= 0){vez = parseInt(7413" ascii
    $s14 = " = 0x8e59;}if(\"acrid\".length === -56452){var l54 = true;}return(IK);}function JT(){var J = 0;if(Math.sin(J) >= 0){var eN = -46" ascii
    $s15 = "var oub = 0;if(Math.asin(oub) != 0){pUa = \"994d88a3\";}else{vvW = true;}function dl(Ueg){return Math.exp(Ueg);}var MM = -1;if(M" ascii
    $s16 = "der\";}else{PX = false;}if(\"kinsmen\".lastIndexOf(\"53795\") < 0){Fw = -924;}else{var YTJ = false;}var cR = 1;if(Math.cos(cR) !" ascii
    $s17 = " 0;if(Math.cos(OM8) > 0){var Bax = 14840;}else{avq = 45266;}var YXe = -1;if(Math.sin(YXe) >= 0){nE = true;}else{var qy = \"berge" ascii
    $s18 = "rn Math.exp(ybt);}function Yw(ta){return Math.acos(ta);}var Xr = 1;if(Math.sin(Xr) == 0){RL = \"514cce4\";}else{Wz = -22105;}var" ascii
    $s19 = "irls\";if(Ite != \"c92d9b\"){wnD = true;}var Ig = 1;if(Math.sin(Ig) != 0){Nnp = \"associating\";}var Jjx = -1;if(Math.asin(Jjx) " ascii
    $s20 = "\";}var oo3 = 1;if(Math.sin(oo3) == 0){var Wn = '';}var b = ZR(Zn);if(\"ae0bf1d\".indexOf(\"906b92b\") != -1){var _yb = '27048';" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}