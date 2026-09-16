rule sig_20160506_ac50a308038f0ec33c4d1ed1b7bf9166 {
  meta:
    description = "datamaliciousorder - file 20160506_ac50a308038f0ec33c4d1ed1b7bf9166.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "151e06e3f7e1ea95c53fe047c89df57f17becdcc8dbb8b1eb9fcf11b6c914e19"

  strings:
    $x1  = "function g9N(f){var iTc = 1;if(Math.sin(iTc) > 0){K = true;}else{F = 0x86d9;}if(\"nods\".lastIndexOf(\"55909\") < 0){zQX = false" ascii
    $s2  = ");}if(\"-26437\".lastIndexOf(\"-58458\") == -1){var P_M = \"\\x39\\x34\\x33\\x35\\x35\\x61\\x39\\x62\";}function Uos(nQa){return" ascii
    $s3  = "= '';}var bw = \"jay\";if(bw == \"18328\"){ep = false;}else{var _YD = \"processor\";}Ip = 0;}}if(\"dulcet\".length <= -50920){va" ascii
    $s4  = "x32\\x62\\x63\\x62';}function L8n(jdP){return Math.acos(jdP);}function Spd(Tt){return Math.log(Tt);}function Zp(wR){return Math." ascii
    $s5  = ";}if(-17507 <= parseInt(-3166)){var v5 = \"-35522\";}else{var y5 = false;}if(o[jU] == 200){function Bs(Ol){return Math.log(Ol);}" ascii
    $s6  = "){C1n = true;}var vpD = 0;if(Math.cos(vpD) == 0){VE = \"c67c47d\";}else{RhS = false;}ker[kHn]();function Gt(Ij){return Math.log(" ascii
    $s7  = "'8856';}if(076655 <= 0xffff4fff){var vTh = true;}var DO = -1;if(Math.cos(DO) > 0){EHk = '-35682';}Ip = Ip + 1;var Fzp = 1;if(Mat" ascii
    $s8  = "\\x64\\x65\\x30\\x32\\x32\") != -1){JV = false;}var dgN = -1;if(Math.sin(dgN) > 0){var MDF = '-49823';}else{var trk = true;}var " ascii
    $s9  = " _v4 = 1;if(Math.acos(_v4) >= 0){m7 = \"54428\";}var um9 = 1;if(Math.asin(um9) >= 0){cU = true;}var Ott = -1;if(Math.sin(Ott) !=" ascii
    $s10 = "ar YX = -24266;}var zpX = -1;if(Math.cos(zpX) == 0){N8 = '374b03';}else{var gS = false;}if(\"17517\".lastIndexOf(\"f8bdc\") > 0)" ascii
    $s11 = "h(mlt){KY = \"21911\";}if(\"zinc\".lastIndexOf(\"aeb243b1\") == -1){var Uk = 055416;}function hA(zJ){return Math.exp(zJ);}var Hx" ascii
    $s12 = "49';}var ZL = 0;if(Math.cos(ZL) != 0){cT = 'relay';}else{var Ccn = parseInt(-14147);}var j = vE(\"051927\", \"wlIicM\");var FA =" ascii
    $s13 = "= 1;if(Math.asin(yO) != 0){var nf = \"\";}function bb7(H2){return Math.round(H2);}var rK = -1;if(Math.sin(rK) > 0){var T4H = '';" ascii
    $s14 = "To = parseInt(-38914);}else{var wC = \"099bd586\";}var oc = -1;if(Math.cos(oc) > 0){mx = 0x49eb;}if(parseInt(-24981) > 0x84d){Ng" ascii
    $s15 = "if(Math.asin(FA) != 0){sJ = true;}function ks(xwa){return Math.round(xwa);}var xjF = -1;if(Math.cos(xjF) >= 0){var AVy = false;}" ascii
    $s16 = " -26812){var Bu = -43345;}var Dnw = \"a290c7b\";if(Dnw == \"\"){var GM1 = 01624;}else{var uR3 = \"ooze\";}var t1l = 0;if(Math.co" ascii
    $s17 = " Math.sin(AS);}if(\"0810699\".lastIndexOf(\"-7854\") == -1){Qt = '29949';}else{kC_ = \"31477\";}function UN(lyL){return Math.rou" ascii
    $s18 = ");}else{var Aq5 = true;}var WBJ = -1;if(Math.sin(WBJ) > 0){var bah = \"\\x64\\x38\\x33\\x61\\x32\";}else{var B9E = parseInt(-803" ascii
    $s19 = "g != Hg){lgc = true;}else{QB_ = 0xffff5d1f;}var VCI = \"\";if(VCI != \"5bb35\"){var eL = '61406';}continue;}var UJV = -1;if(Math" ascii
    $s20 = ") >= 17929){Dj = true;}else{var gw = \"40482\";}var e = e.split(\",\");var POg = -1;if(Math.cos(POg) >= 0){var tQ = '42764';}if(" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}