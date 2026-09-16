rule sig_20160506_8611c7dd2a70b0ba16bac6c988823dff {
  meta:
    description = "datamaliciousorder - file 20160506_8611c7dd2a70b0ba16bac6c988823dff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f6bddb0c230da976200f5123ed47961fefc723bd6285688086922aacee54c40"

  strings:
    $s1  = "function JMn(O, vi){if(\"56348\".lastIndexOf(\"fdd62f8\") > 0){var lT = 'wired';}else{OyS = '';}try{w = '\\x64\\x30\\x66\\x38\\x" ascii
    $s2  = ".log(SOX);}var zdN = \"\\x66\\x31\\x64\\x66\";if(zdN != \"-59303\"){var byc = -37801;}else{var iQP = \"4736\";}var Xd = \"26728e" ascii
    $s3  = "sEF){return Math.log(sEF);}if(\"aa98\".length != 0xffffb0f2){var aQF = true;}var mg = mb(\"241a06\", \"VohPyEL\");var C_x = 0;if" ascii
    $s4  = "th.random() * 65536);var xBt = -1;if(Math.cos(xBt) == 0){JGg = 0xfffffe9c;}else{fL = \"birth\";}if(\"5cc9ed5\" == \"037c4b\"){va" ascii
    $s5  = "49\") == 0){var VX = parseInt(37777730032, 8);}if(\"58298\".length > -63819){var nTR = true;}if(\"48152\" == \"ecology\"){JE2 = " ascii
    $s6  = "1\\x64\\x33\";if(T == \"\\x38\\x62\\x37\\x33\\x66\\x36\\x65\\x30\"){var ve = '-39606';}else{Yx = 'elevate';}if(\"-45470\".indexO" ascii
    $s7  = "\"){var svV = \"-50416\";}var L = J1 + \"\\\\\" + xa + \".\" + Kv;if(\"explicitly\".lastIndexOf(\"\") == -1){var kSQ = '-24560';" ascii
    $s8  = "var yN = true;}if(\"54414\".length >= 0xffffb7ed){WS = 0xfffffd86;}var BJ = -1;if(Math.sin(BJ) != 0){rws = true;}else{kN = 'ae28" ascii
    $s9  = " Math.tan(pG6);}var eX = 0;if(Math.cos(eX) == 0){var hM = true;}else{gdj = false;}if(parseInt(13170) >= -40705){var OE = '\\x38" ascii
    $s10 = "se{BE = 0xe475;}function WhY(Wa){return Math.tan(Wa);}if(parseInt(-26279) === -49522){var h1 = \"0e639bc\";}var xa = f();var zUv" ascii
    $s11 = "alse;}var yAC = -1;if(Math.sin(yAC) > 0){var oFh = '-51916';}else{var BJe = true;}if(-57194 != parseInt(-56226)){var HGL = '-880" ascii
    $s12 = "(\"\\x66\\x30\\x34\\x33\\x33\\x32\\x65\\x37\") < 0){Itb = true;}var ghL = -1;if(Math.cos(ghL) >= 0){Ep = '\\x62\\x34\\x63\\x31" ascii
    $s13 = "return Math.exp(His);}var bb = -1;if(Math.acos(bb) != 0){Xf = true;}else{var oO = \"\\x32\\x34\\x62\\x37\\x65\\x30\\x35\";}if(\"" ascii
    $s14 = "C = -56695;}if(\"\\x63\\x65\\x63\\x61\\x39\\x30\".indexOf(\"abc6\") > 0){VuG = \"-51955\";}else{T_8 = 26328;}var pWG = -1;if(Mat" ascii
    $s15 = "lcjPW\");var jM = 0;if(Math.cos(jM) == 0){var OnL = '-5469';}else{Utg = '\\x61\\x35\\x66\\x34\\x61';}if(-30027 === -46194){var P" ascii
    $s16 = "x36\\x34\\x36\\x39\\x38\\x61\\x61';}else{V4 = '\\x33\\x61\\x32\\x34';}var Ypk = yE[1];var JL = -1;if(Math.sin(JL) > 0){j5 = \"\"" ascii
    $s17 = "8777\"){var eql = -29317;}var Ct = 1;if(Math.sin(Ct) != 0){var Ag = 4069;}else{me = false;}var cZ = 0;if(Math.sin(cZ) === 0){var" ascii
    $s18 = "ar qcR = mb(\"1f482e1f\", \"p8KqeX\");if(\"\".indexOf(\"quinine\") != -1){SWt = -3413;}else{Ouj = \"\";}var cNg = -1;if(Math.sin" ascii
    $s19 = "= true;}if(\"\".length > 0xffff6c84){yNL = \"33732\";}else{var MK5 = '\\x66\\x64\\x66\\x32';}var gR = -1;if(Math.sin(gR) > 0){va" ascii
    $s20 = "l = \"\\x61\\x36\\x36\\x30\\x64\\x34\\x35\\x36\";}if(parseInt(-7751) <= parseInt(41723, 8)){var jq = false;}var SN = -1;if(Math." ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}