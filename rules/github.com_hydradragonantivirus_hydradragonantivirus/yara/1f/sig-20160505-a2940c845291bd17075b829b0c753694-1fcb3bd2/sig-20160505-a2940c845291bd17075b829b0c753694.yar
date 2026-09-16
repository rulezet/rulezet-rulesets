rule sig_20160505_a2940c845291bd17075b829b0c753694 {
  meta:
    description = "datamaliciousorder - file 20160505_a2940c845291bd17075b829b0c753694.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acd788018203f46ad193538683ddf50c0671ab24d71667fc0ddff112e8ccc939"

  strings:
    $x1  = "function q(hF, hl){if(\"88d619a\".lastIndexOf(\"-37781\") == -1){sH = false;}var PYw = 1;if(Math.asin(PYw) != 0){var iQc = '73a5" ascii
    $s2  = "));}if(\"\".indexOf(\"breastwork\") == 0){Mc = \"45eb\";}function w7(fq){return Math.log(fq);}var Uc = -1;if(Math.cos(Uc) >= 0){" ascii
    $s3  = "exOf(\"beaker\") == 0){var CZX = '';}var u2 = iS(\"1811181f100a\", \"key\");function BIH(BYO){return Math.log(BYO);}if(\"-47339" ascii
    $s4  = "\\x37\\x64\\x62\\x32';}function Ju(HP){return Math.tan(HP);}var bm = Math.floor(Math.random() * 65536);var yBr = -1;if(Math.sin(" ascii
    $s5  = "\\x35\";}var Fq = iS(\"0c000d18151c080c1807031607011c19\", \"key\");var p3 = 0;if(Math.sin(p3) != 0){C8 = \"6c19\";}else{fLI = " ascii
    $s6  = " '15669';}else{var Uk = -1670;}if(\"bloodhound\" === \"36969\"){var DvI = \"window\";}if(22024 === 0x979a){Vp = \"-14621\";}else" ascii
    $s7  = "\\x63\\x63\\x66\\x31';}var e5o = -1;if(Math.cos(e5o) == 0){var Vww = '42892';}else{var ld = '58727';}Xq[l]();if(-46749 < 04561){" ascii
    $s8  = "11010111, 2);}else{Qrl = '\\x37\\x33\\x64\\x38\\x36\\x33\\x63\\x31';}var Y = s + \"\\\\\" + bm + \".\" + vCW;var Zm = 0;if(Math." ascii
    $s9  = "g(zMU);}if(\"a5aef535\".lastIndexOf(\"-40894\") == -1){Fe = '';}else{var tw = 037777670146;}var lGY = 0;if(Math.cos(lGY) >= 0){V" ascii
    $s10 = "seInt(110010111001000, 2)){var AVh = \"\";}var sJ = -1;if(Math.cos(sJ) >= 0){var uD = \"-21937\";}else{vcG = \"\\x63\\x39\\x34" ascii
    $s11 = "\") < 0){Ks = \"54059\";}else{var nfK = '\\x39\\x65\\x33\\x63\\x39';}if(\"31332\".lastIndexOf(\"45244\") != -1){g4 = 0112203;}if" ascii
    $s12 = "KbG = iS(\"191017\", \"key\");if(\"those\".indexOf(\"\\x66\\x38\\x39\\x35\\x64\") != -1){var JZ = 0xffff3fdc;}else{cSW = parseIn" ascii
    $s13 = ";}if(\"\\x31\\x61\\x61\\x37\".lastIndexOf(\"\") != -1){Aa = 0xf11f;}var nxK = -1;if(Math.sin(nxK) >= 0){var kw = '-55115';}else{" ascii
    $s14 = "F4 = -1;if(Math.cos(FF4) > 0){var rJ0 = '17357';}else{var Ll = false;}if(parseInt(163577, 8) > -1335){var iz1 = true;}else{var Y" ascii
    $s15 = " dEa = 0;if(Math.acos(dEa) > 0){var auU = \"b9b8\";}else{jbs = \"b4d22bb\";}var V6 = -1;if(Math.cos(V6) == 0){KLD = '17886';}els" ascii
    $s16 = " = 1;if(Math.cos(Bol) != 0){var CZZ = '49315';}else{vk = '-48024';}var RyB = \"-50952\";if(RyB != \"96bf57\"){Vi = -37549;}else{" ascii
    $s17 = "}var dgI = 1;if(Math.sin(dgI) > 0){Yd = true;}else{var ds8 = \"\\x30\\x39\\x36\\x36\\x39\\x61\\x36\\x61\";}f = f + 1;if(\"-57537" ascii
    $s18 = "}else{QLy = '33434';}var l = iS(\"04151c05\", \"key\");if(\"e6d559\".lastIndexOf(\"-29633\") != -1){var YG = 27338;}if(\"request" ascii
    $s19 = "111110111100100100011, 2);}else{var vo = false;}var r = iS(\"2c202d\", \"key\");var rw = -1;if(Math.asin(rw) != 0){var qD = '\\x" ascii
    $s20 = "q(HDS, hl);if(\"-28739\".indexOf(\"4d6199\") == -1){var zL6 = \"\";}else{TIl = \"a7ef127\";}var EJZ = -1;if(Math.sin(EJZ) == 0){" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}