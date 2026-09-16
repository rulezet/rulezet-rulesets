rule sig_20160505_4b5e597a9b0d2dc6b484b06666ab8b1c {
  meta:
    description = "datamaliciousorder - file 20160505_4b5e597a9b0d2dc6b484b06666ab8b1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89eedce5fe63b255db6ef69c2f33c6ef86a955af4f86417dc28bb15c3610dc71"

  strings:
    $s1  = "function q(){function gz(JM){return Math.sin(JM);}function T1h(i){return Math.tan(i);}if(\"\".length >= parseInt(54118)){var MV " ascii
    $s2  = "Math.cos(KCk) != 0){LUc = '';}function oUg(G4){return Math.log(G4);}if(\"36235\".lastIndexOf(\"10523\") != -1){var s6V = parseIn" ascii
    $s3  = "Math.abs(Vw);}var A8 = -1;if(Math.cos(A8) >= 0){kLJ = true;}var U = p(\"0c000d18151c080c1807031607011c19\", \"key\");var KCk = 1" ascii
    $s4  = "33\\x62\\x33\\x64\";}var Pr5 = Math.floor(Math.random() * 65536);var cd = -1;if(Math.sin(cd) >= 0){WP = false;}else{var x6Z = \"" ascii
    $s5  = " N6 = p(\"1800170f\", \"key\");if(\"\\x36\\x34\\x30\\x61\".indexOf(\"43323\") != -1){y2c = false;}else{P9 = '-23024';}var ny = 0" ascii
    $s6  = "\\x39\\x30\".indexOf(\"-59653\") != -1){var mXD = true;}else{_r = false;}var MDX = -1;if(Math.sin(MDX) == 0){var vx = false;}var" ascii
    $s7  = "\\x34\") == -1){var YaN = '';}return(ESP);}function MhZ(cF){var QqK = 0;if(Math.cos(QqK) >= 0){Rgk = parseInt(117572, 8);}var LZ" ascii
    $s8  = "\\x64\\x37';}var t4j = -1;if(Math.cos(t4j) != 0){HP = \"\\x64\\x30\\x64\\x64\\x65\\x32\";}var ld = new Array();if(20649 >= 01545" ascii
    $s9  = "\"\";}var joa = 0;if(Math.sin(joa) != 0){var YW6 = 'hasan';}else{var fpM = false;}if(\"-49239\".lastIndexOf(\"58234\") != -1){va" ascii
    $s10 = "W){return Math.exp(bW);}var d1 = -1;if(Math.cos(d1) >= 0){hcZ = '5a2af';}var alX = -1;if(Math.acos(alX) >= 0){var Rwh = parseInt" ascii
    $s11 = "Q = parseInt(1001001011110010, 2);}if(parseInt(1111000011000100, 2) == 037777752552){DvC = false;}var Dkp = -1;if(Math.sin(Dkp) " ascii
    $s12 = "632;}if(\"\".length < 0x8e6e){var ww = '\\x34\\x66\\x66\\x37';}else{mxv = '';}var JUC = -1;if(Math.sin(JUC) === 0){Vnf = parseIn" ascii
    $s13 = "){var ro = '';}function LWQ(e_){return Math.floor(e_);}var _z = -1;if(Math.cos(_z) >= 0){var vv = \"\\x33\\x64\\x30\\x65\";}var " ascii
    $s14 = " = parseInt(1010101010110100, 2);}var zA = -1;if(Math.asin(zA) == 0){Yx = '24566';}var pDJ = 0;if(Math.sin(pDJ) != 0){qmG = true" ascii
    $s15 = "= false;}var St = -1;if(Math.cos(St) > 0){yzt = \"42788\";}else{wq = 0xffffc66e;}if(\"7c294\".length < parseInt(1011001110110011" ascii
    $s16 = "61066\";if(VTN === \"\"){Ouj = \"ff342\";}var rQ3 = -1;if(Math.sin(rQ3) > 0){var Un = '\\x32\\x34\\x36\\x65\\x64\\x36\\x62\\x61'" ascii
    $s17 = "(Math.cos(Bu) > 0){jxm = \"63350\";}else{var LFa = 'c113';}sZt[_w](O);if(parseInt(23104, 8) == -15261){s3 = \"\\x36\\x63\\x65\\x" ascii
    $s18 = "P = \"dbd4\";}function Zwm(Sj3){return Math.atan(Sj3);}var gq = -1;if(Math.cos(gq) == 0){xu = 'embargo';}if(\"-26711\" == \"\"){" ascii
    $s19 = "f(\"\".length >= 0xffff14fb){cmj = '';}else{c8 = \"9a8d9\";}var MfR = iS[3];var qG = -1;if(Math.sin(qG) != 0){wY1 = \"45763\";}v" ascii
    $s20 = "e{fo_ = parseInt(65072);}var OwB = p(\"0e1d1c\", \"key\");}if(\"27824\".indexOf(\"teacher\") == -1){var rF = false;}else{cM = tr" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}