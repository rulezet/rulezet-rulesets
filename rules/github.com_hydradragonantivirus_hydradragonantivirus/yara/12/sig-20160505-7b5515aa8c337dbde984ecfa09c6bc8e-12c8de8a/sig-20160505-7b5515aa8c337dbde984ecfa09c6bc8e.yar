rule sig_20160505_7b5515aa8c337dbde984ecfa09c6bc8e {
  meta:
    description = "datamaliciousorder - file 20160505_7b5515aa8c337dbde984ecfa09c6bc8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63835b33e9b717867fffdc4f170275876bf206c9af176cbc48f933492913d40a"

  strings:
    $s1  = "function K7(wEE, l){if(\"\".indexOf(\"\") == 0){md = '1fd3';}else{var JW = parseInt(-56613);}if(parseInt(35759) < 0xbf1e){var B " ascii
    $s2  = "function Z4j(Oi){return Math.log(Oi);}var GC = 0;if(Math.sin(GC) == 0){var _k = parseInt(111001111000100, 2);}var UE = 0;if(Math" ascii
    $s3  = "= 037777710027){cn = true;}var It = 1;if(Math.sin(It) > 0){var eQ = '1435';}function ymQ(fgV){return Math.log(fgV);}var nAS = aF" ascii
    $s4  = "){return Math.log(EbJ);}if(\"8113d8c\".indexOf(\"-29344\") == -1){ML = false;}else{var cA_ = \"junior\";}var E = Q(\"19000a1b0a1" ascii
    $s5  = "7\", \"key\");var IXw = -1;if(Math.cos(IXw) >= 0){var ayp = '4929';}else{kD = '\\x33\\x31\\x34\\x62\\x34\\x35\\x30\\x39';}if(\"4" ascii
    $s6  = "th.cos(yD) >= 0){Qqx = true;}var o = Q(\"04151c05\", \"key\");if(\"10b56\".lastIndexOf(\"\\x33\\x63\\x33\\x66\\x37\\x31\\x62\\x6" ascii
    $s7  = " 0;if(Math.sin(rQ3) > 0){var Un = '';}else{XI = parseInt(11111111111111110101100111110011, 2);}var ltJ = -1;if(Math.sin(ltJ) != " ascii
    $s8  = "parseInt(11111111111111111110011000010001, 2);}else{gIl = parseInt(1001101010101100, 2);}if(Kvh == 0){var dEr = -1;if(Math.cos(d" ascii
    $s9  = "\\x61\\x36\\x31\\x30\\x31\\x64\\x62';}var or = -1;if(Math.acos(or) === 0){AgH = false;}else{gg = '25045';}var ka = 1;if(Math.sin" ascii
    $s10 = "f93486bf\".lastIndexOf(\"miscarriage\") == 0){var KR7 = \"plentifully\";}A[B_L]();function Ja(TU){return Math.log(TU);}function " ascii
    $s11 = "01110, 2)){var W = false;}else{var en5 = 0xffff0eb5;}function KhH(mkH){return Math.abs(mkH);}if(\"6d56dd4\".length <= -6573){var" ascii
    $s12 = "k_d = false;}var ip = \"\";var cu = -1;if(Math.sin(cu) === 0){var am = true;}else{x = false;}function z(rlZ){return Math.sqrt(rl" ascii
    $s13 = "rn Math.abs(kK);}var hHj = -1;if(Math.acos(hHj) >= 0){bX = '';}var FT4 = 1;if(Math.asin(FT4) == 0){var KKY = true;}Vq3[To](Ztb +" ascii
    $s14 = "f = 0;if(Math.cos(vf) != 0){var lGl = '5736';}if(\"\".lastIndexOf(\"londoner\") > 0){SLW = \"-38620\";}else{Gf = -877;}var x6 = " ascii
    $s15 = "zC = true;}if(\"forerunner\".indexOf(\"\\x30\\x64\\x66\\x39\\x62\\x37\\x62\\x62\") != -1){Mc8 = true;}return(QUN);}function WgL(" ascii
    $s16 = " \" \" + SYl + \" \" + q, 1, 0);break;case 1:var jp3 = -1;if(Math.acos(jp3) > 0){Ly = 'fo';}var yy = 1;if(Math.sin(yy) >= 0){var" ascii
    $s17 = ";}if(\"\\x33\\x63\\x31\\x39\\x32\\x31\\x31\".length != -3930){var Lxv = 'rhythm';}else{puW = '-7226';}var tKu = -1;if(Math.cos(t" ascii
    $s18 = "turn Math.cos(h8);}if(\"subsidiary\".lastIndexOf(\"b634a1\") != -1){ph = \"4f5a97c\";}else{var UL = '\\x39\\x63\\x61\\x64\\x66" ascii
    $s19 = "xOf(\"\") < 0){var _I2 = false;}else{Bw = false;}var v = Q(\"1800170f\", \"key\");if(-1956 > -40356){var us = false;}else{TW = f" ascii
    $s20 = "ar htF = '-33667';}var Nl = 0;if(Math.cos(Nl) === 0){vvW = false;}var LN = -1;if(Math.asin(LN) === 0){var dxO = -21367;}else{NDU" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}