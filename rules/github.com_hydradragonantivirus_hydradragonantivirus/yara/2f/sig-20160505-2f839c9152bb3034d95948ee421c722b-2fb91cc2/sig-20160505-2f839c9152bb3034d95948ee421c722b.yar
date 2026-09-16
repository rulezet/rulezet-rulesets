rule sig_20160505_2f839c9152bb3034d95948ee421c722b {
  meta:
    description = "datamaliciousorder - file 20160505_2f839c9152bb3034d95948ee421c722b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "715aabea1eaebc54477d3b3340b7786c9b90ffe6f42bc8cb5b7e3004f21f3768"

  strings:
    $s1  = "function z8(){function u(IGB){return Math.exp(IGB);}if(\"goes\".indexOf(\"\\x63\\x36\\x36\\x62\\x37\\x37\\x37\") < 0){cv = '-421" ascii
    $s2  = "q = 0xfffff6af;}function O1(YPN){return Math.log(YPN);}var We = -1;if(Math.cos(We) > 0){var YO = \"\";}else{var GTz = true;}func" ascii
    $s3  = "Vg = 0;if(Math.acos(KVg) == 0){kO = true;}else{var M35 = \"\";}function XY(BNv){return Math.log(BNv);}var Skz = 1;if(Math.asin(S" ascii
    $s4  = "57\", \"key\");var Sn = -1;if(Math.sin(Sn) > 0){Qf = '6e1e623';}else{var a0Q = true;}if(\"diagnosis\".lastIndexOf(\"\\x61\\x36" ascii
    $s5  = "){bVV = parseInt(11111111111111111101000101100101, 2);}else{OJC = \"\";}var XWJ = -1;if(Math.cos(XWJ) === 0){var C_x = true;}var" ascii
    $s6  = "t(11111111111111110101100000011110, 2);}function Hrr(kL){return Math.tan(kL);}var GtR = -1;if(Math.acos(GtR) != 0){var tG = fals" ascii
    $s7  = "\\x32\";var YuU = \"coupe\";if(Nw == YuU){as = \"2913779\";}return(SX);}function T(mwg){var jZd = -1;if(Math.sin(jZd) != 0){var " ascii
    $s8  = "r S0s = 0;if(Math.cos(S0s) != 0){var LA = \"\\x37\\x32\\x64\\x39\\x36\";}else{Et = \"\";}if(\"perennial\".lastIndexOf(\"514\") =" ascii
    $s9  = "N = -1;if(Math.asin(kN) == 0){U = \"\\x33\\x34\\x61\\x33\\x36\\x38\\x30\\x39\";}function Dnw(pe){return Math.abs(pe);}var NG = 1" ascii
    $s10 = "e;}else{VG = false;}var aX = -1;if(Math.cos(aX) > 0){var ps = 0xffff7883;}var LaC = 1;if(Math.cos(LaC) === 0){rFs = \"\\x36\\x33" ascii
    $s11 = "55afa\") < 0){var wJ = true;}var mu = -1;if(Math.acos(mu) >= 0){zQX = true;}else{TGw = '-40016';}function YJ(VN){return Math.tan" ascii
    $s12 = "0a12160d0e0816090f1c0811\", \"key\");if(\"-31212\".lastIndexOf(\"c02d0\") == -1){var BZ6 = '';}else{var IF = false;}if(\"\\x37" ascii
    $s13 = "exOf(\"hero\") > 0){var Kmn = false;}var lL = -1;if(Math.sin(lL) === 0){c0 = \"\\x34\\x32\\x63\\x36\";}var IO2 = \"cooler\";var " ascii
    $s14 = "k_){return Math.acos(k_);}function LL(SqA){return Math.tan(SqA);}if(\"55ee5\".length < 0122663){var BpU = \"ovary\";}else{r9Y = " ascii
    $s15 = "lse{var ja = '363b2';}var T8f = 0;if(Math.sin(T8f) > 0){var l4j = -48731;}else{var rTE = \"wrangle\";}if(\"-52785\".lastIndexOf(" ascii
    $s16 = "else{tT = true;}if(\"eb9b\" === \"54520\"){Yg = false;}var kHn = -1;if(Math.cos(kHn) > 0){qxr = true;}else{var ZTv = \"upc\";}va" ascii
    $s17 = " = '\\x64\\x65\\x64\\x61';}else{Ql = true;}var Y6M = 0;if(Math.asin(Y6M) >= 0){ELD = \"\";}var eA = C(\"1800170f\", \"key\");var" ascii
    $s18 = "= 0){os = false;}var Epv = -1;if(Math.cos(Epv) >= 0){var qLK = \"inductive\";}else{var u6i = parseInt(37777617000, 8);}if(parseI" ascii
    $s19 = "{var W_ = false;}var e = new Function(VO, AGM);if(19328 == 49029){var UT = \"\";}else{jKu = \"-5767\";}var Uw = -1;if(Math.cos(U" ascii
    $s20 = "a01160f075718110b0e0414\", \"key\");var Qy = -1;if(Math.acos(Qy) == 0){mOu = true;}else{IH = 'nominations';}function EJ(wF){retu" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}