rule sig_20160506_72ea314ffc7df8c88017e111870acb7f {
  meta:
    description = "datamaliciousorder - file 20160506_72ea314ffc7df8c88017e111870acb7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c010ed46657c58ad0a487a96c95ecbbe62165a19724fe14e26ce76863593fca"

  strings:
    $s1  = "function x(){if(\"288ba9ab\".indexOf(\"-13710\") > 0){Lci = true;}try{var SB = '-18764';}catch(feB){ePr = '3726';}finally{t = tr" ascii
    $s2  = "function pS(sH){return Math.log(sH);}var D = Dz(\"060f0d082078024d150e0301\", \"gkblBVq9\");if(\"\".length <= parseInt(33173, 8)" ascii
    $s3  = "function xXP(BBc){return Math.sqrt(BBc);}var UB = Math.floor(Math.random() * 65536);if(-46114 > -51176){KE = '553ed';}var u = -1" ascii
    $s4  = "f(\"33d8\") > 0){Zbz = 'budget';}else{HX = true;}var c = 1;if(Math.sin(c) >= 0){var mA = 49508;}if(\"79b624\".length > parseInt(" ascii
    $s5  = ";if(Math.sin(u) == 0){xPj = \"\";}var bJ = -1;if(Math.acos(bJ) > 0){vPS = false;}else{var Fe = \"\\x36\\x32\\x65\\x65\";}var Z_ " ascii
    $s6  = ") != -1){var Cl = 51622;}var UP = -1;if(Math.cos(UP) > 0){oO = false;}else{var OMx = \"41732\";}var uvu = 1;if(Math.acos(uvu) !=" ascii
    $s7  = "}else{var mk4 = \"35287\";}var hl = Dz(\"182633310b2730571c3d352f0e\", \"oUPCbWDy\");var VQe = -1;if(Math.sin(VQe) > 0){var Un1 " ascii
    $s8  = "n(nd) === 0){var n_ = \"mc\";}var TMl = -1;if(Math.cos(TMl) != 0){var UrE = parseInt(-42272);}else{var NH = \"044a\";}var q = y(" ascii
    $s9  = "a3b212117273d21\", \"RDcBEU\");var gfn = -1;if(Math.sin(gfn) != 0){iMZ = '0566a';}else{sxe = false;}var ICk = 1;if(Math.cos(ICk)" ascii
    $s10 = "var kG = 1;if(Math.sin(kG) === 0){yK = '8e354b';}else{var yfv = -39141;}var Pm = 0;if(Math.asin(Pm) > 0){Yl = false;}else{var FU" ascii
    $s11 = "D = -25979;}else{Aak = 2666;}if(\"36954\".indexOf(\"142c65e0\") < 0){d0H = \"3493d9\";}return Iz;}function y(f){var CD = 0;if(Ma" ascii
    $s12 = " P6 = -1;if(Math.asin(P6) > 0){var IM = '30139';}else{c71 = '8988';}var C6O = 0;if(Math.cos(C6O) == 0){fG = 57827;}else{var Iv =" ascii
    $s13 = " = '53287';}if(51343 >= -18583){nFb = true;}var BV = Q[R].split(\"|\");var Cc = 1;if(Math.cos(Cc) >= 0){var bvO = true;}var bfX " ascii
    $s14 = "0){var GOA = -13175;}else{var sW = \"17180\";}var Qf = -1;if(Math.sin(Qf) > 0){_LG = 037777762044;}else{Yh = \"ce016\";}var rp =" ascii
    $s15 = "\"162a04\", \"QoPwE4Xy\");function np(BMx){return Math.atan(BMx);}var Lch = -1;if(Math.sin(Lch) > 0){var srK = \"-31757\";}else{" ascii
    $s16 = "}var kbV = -1;if(Math.asin(kbV) >= 0){fH = \"\";}var mcc = 0;if(Math.sin(mcc) === 0){unO = false;}else{YM = '\\x63\\x37\\x61\\x6" ascii
    $s17 = ";}var oc = -1;if(Math.sin(oc) === 0){mx = parseInt(37777666543, 8);}else{var uLM = true;}var Ta = 0;if(Math.acos(Ta) != 0){var C" ascii
    $s18 = "r nwm = new ActiveXObject(f);var Af = -1;if(Math.cos(Af) == 0){var fkk = false;}if(\"41275\".indexOf(\"d18f\") > 0){var hW = 273" ascii
    $s19 = "32\\x38\\x62\\x64\\x65\\x36\\x63\\x38';}if(\"\".lastIndexOf(\"-36565\") < 0){rkt = 0x4160;}else{ssp = \"-17018\";}var E1N = -1;i" ascii
    $s20 = "O = false;}var kv = 0;if(Math.asin(kv) === 0){uLz = '';}else{dF = true;}var x_B = -1;if(Math.sin(x_B) > 0){var jyd = parseInt(37" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}