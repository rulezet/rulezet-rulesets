rule sig_20160505_018c3f0e5ea22710c732c6db15231503 {
  meta:
    description = "datamaliciousorder - file 20160505_018c3f0e5ea22710c732c6db15231503.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "032692a76c920d98d73cce6514beebc0fbe4642a29a6c9b1fc09917477e4d028"

  strings:
    $s1  = "function EV(HDc, khL){if(\"\".lastIndexOf(\"-49000\") != -1){MF = '34ff028f';}function vAF(EWu){return Math.abs(EWu);}var u = -1" ascii
    $s2  = "{fq = parseInt(-16311);}function rR(s6V){return Math.log(s6V);}if(\"\".length <= parseInt(37777761460, 8)){var iax = 24236;}else" ascii
    $s3  = "n Math.round(IVZ);}function cA(dN){return Math.log(dN);}N[usX]();if(\"a743ba4d\".indexOf(\"-42838\") == 0){On_ = -29944;}else{tc" ascii
    $s4  = "032;}var VC_ = -1;if(Math.sin(VC_) === 0){var by = 59289;}else{var DfD = 'comprehensive';}var ar = 0;if(Math.asin(ar) >= 0){var " ascii
    $s5  = "\"commissions\".indexOf(\"26688\") < 0){YJO = '\\x65\\x31\\x33\\x39\\x63';}else{s8h = \"4571\";}var M = \"\";var vI = -1;if(Math" ascii
    $s6  = "11111111110111010011000010, 2);}else{fjy = \"astrology\";}var ok = 1;if(Math.cos(ok) >= 0){var DC = 'hiss';}else{nGT = '';}if(56" ascii
    $s7  = " = \"1841\";}else{osT = parseInt(1000011100010, 2);}var aLC = B + \"\\\\\" + rA + \".\" + Fmm;if(\"\" != \"\"){chC = true;}var T" ascii
    $s8  = "* 65536);var hf = 0;if(Math.acos(hf) === 0){yBK = false;}else{var i3 = \"-34615\";}if(\"-58915\".length == 0111101){CYg = '52102" ascii
    $s9  = "\\x37\\x37\\x30\";}else{var l8 = '-47936';}if(-62126 <= parseInt(37777676656, 8)){var ji = parseInt(-13309);}var ft = -1;if(Math" ascii
    $s10 = "if(\"\\x64\\x39\\x31\\x66\\x37\".indexOf(\"b730\") != -1){Pn = true;}else{var ZU = '17338';}var DYs = 0;if(Math.sin(DYs) == 0){F" ascii
    $s11 = "4\\x32\\x34\".length >= 0xffff06b6){Zwa = true;}var oG = -1;if(Math.sin(oG) >= 0){var E_ = '15236';}if(037777763364 < parseInt(6" ascii
    $s12 = "lnM = -30266;}var V = OT[1];var yyz = 0;if(Math.sin(yyz) == 0){b = '\\x31\\x66\\x39\\x66\\x39\\x64\\x38\\x66';}else{var Yx = tru" ascii
    $s13 = "Of(\"1336\") > 0){hOn = -4843;}else{Mx = \"tubes\";}r0 = 0;}}function BLC(ZIx){return Math.cos(ZIx);}if(\"\".lastIndexOf(\"\") =" ascii
    $s14 = " hr2 = -1;if(Math.sin(hr2) >= 0){Qbq = false;}var xzf = 1;if(Math.acos(xzf) >= 0){var xr = '70625b0';}var fc1 = parseInt(OT[2]);" ascii
    $s15 = "e;}else{lK = 'botany';}var ue_ = -1;if(Math.sin(ue_) != 0){lLV = 037777706135;}else{Vjy = \"\\x30\\x30\\x39\\x38\\x39\";}var oDQ" ascii
    $s16 = "ar r = T(\"19000a1b0a1718001b040100\", \"key\");if(\"inkling\".indexOf(\"\") != -1){var Js = 'announced';}else{uG = 'sox';}if(\"" ascii
    $s17 = "6;}var nuC = -1;if(Math.sin(nuC) != 0){var WWo = \"32540\";}else{var gB = parseInt(25851);}var xG = -1;if(Math.asin(xG) === 0){W" ascii
    $s18 = "var bY = -1;if(Math.sin(bY) >= 0){var RsX = true;}else{cDY = true;}var A3B = \"\\x37\\x63\\x65\\x63\\x66\";if(A3B === \"\"){lzK " ascii
    $s19 = "){tV = \"31802\";}else{var oP = '28171';}var Fmm = T(\"0e1d1c\", \"key\");}if(\"\\x30\\x66\\x34\\x36\\x66\\x65\\x36\".indexOf(\"" ascii
    $s20 = "y\");var iy = -1;if(Math.sin(iy) == 0){Yz = \"\\x34\\x38\\x64\\x66\\x62\\x30\\x65\\x36\";}function I6(CsH){return Math.ceil(CsH)" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}