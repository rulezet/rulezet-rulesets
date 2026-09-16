rule sig_20160505_7ca1ce050124b4f83a0da186f6eb7369 {
  meta:
    description = "datamaliciousorder - file 20160505_7ca1ce050124b4f83a0da186f6eb7369.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62e9abbaba34751a0b99f2024713fb2e737fbec1dba6e8b067b847979fbab69b"

  strings:
    $x1  = "function w(KF, MuS){function oA(s3C){return Math.asin(s3C);}if(\"7028\".lastIndexOf(\"-53955\") == -1){var L = false;}var yR = 1" ascii
    $s2  = "){var Bwg = parseInt(-13115);}if(\"corked\" === \"\"){var pN = false;}function GR(ET){return Math.log(ET);}var s = FT4(\"191017" ascii
    $s3  = "var Z = vz + \"\\\\\" + kT + \".\" + nMX;function I0(znN){return Math.exp(znN);}if(\"-43094\".indexOf(\"\") != -1){var pJg = fal" ascii
    $s4  = "f(dD != uOQ){UD = \"50395\";}if(\"\".indexOf(\"disembark\") != -1){Qc = false;}function mW(Dy){return Math.tan(Dy);}Ap0 = Ap0 + " ascii
    $s5  = "Math.sin(yR) > 0){N = parseInt(1111111110000110, 2);}else{var b = \"andrea\";}var Ppd = \"\";if(\"\".indexOf(\"\\x38\\x39\\x39" ascii
    $s6  = "Math.acos(cv) === 0){QF = \"\\x39\\x30\\x38\\x30\\x37\\x35\\x65\";}function gfQ(Hbo){return Math.abs(Hbo);}if(\"\".length <= -56" ascii
    $s7  = " '032815a';}return(g);}function tW(){var dpB = -1;if(Math.sin(dpB) == 0){lP = true;}if(parseInt(11111111111111111011011010001011" ascii
    $s8  = "C = -1;if(Math.acos(htC) != 0){Dz = '';}else{var WSo = true;}var iy = FT4(\"0c000d18151c080c1807031607011c19\", \"key\");var SdE" ascii
    $s9  = "N = '';}else{var bSV = parseInt(11111111111111110000100000110100, 2);}var gYL = -1;if(Math.sin(gYL) != 0){var s6V = 0xb53;}else{" ascii
    $s10 = "= 0x66af){QrQ = \"\\x39\\x30\\x31\\x32\\x61\";}var ZBC = -1;if(Math.cos(ZBC) >= 0){var bV = 072124;}else{MtB = 24548;}var GC = 1" ascii
    $s11 = "JP) >= 0){var Hqj = \"\\x36\\x39\\x66\\x36\\x65\\x66\";}else{ds = \"\";}function ol(Eq){return Math.acos(Eq);}var joV = -1;if(Ma" ascii
    $s12 = "0x62f;}var kT = Math.floor(Math.random() * 65536);var WnH = 1;if(Math.cos(WnH) === 0){var N_t = 46425;}else{zWd = 0x7562;}var Oz" ascii
    $s13 = "= -1){var CYD = false;}UuS[O](VMY);function QVX(_o){return Math.cos(_o);}if(parseInt(1110000110100010, 2) != parseInt(3777762476" ascii
    $s14 = "y\");var WHI = -1;if(Math.sin(WHI) >= 0){YM = parseInt(26648);}else{var Pt = false;}var eqI = -1;if(Math.asin(eqI) >= 0){var NR " ascii
    $s15 = " 0){var Q3 = 29189;}else{eqX = false;}var fH = -1;if(Math.sin(fH) === 0){cO = \"2bbb6e4f\";}function sy(LB){return Math.abs(LB);" ascii
    $s16 = "var nHn = '-20670';}var vQT = FT4(\"0a01160f075718110b0e0414\", \"key\");if(\"\".indexOf(\"\") != -1){var yus = 0xffff0af6;}else" ascii
    $s17 = "\"65798\") != -1){MN = true;}if(\"-7807\".indexOf(\"-63183\") > 0){var aJt = \"\\x65\\x66\\x34\\x63\\x35\";}var bR = 1;if(Math.c" ascii
    $s18 = ", 2) < parseInt(10011110011011, 2)){var Up = true;}if(\"an\".length != -40424){nFe = \"a485\";}var nN = 0;if(Math.cos(nN) != 0){" ascii
    $s19 = " = \"mandolin\";if(Oz == \"\\x63\\x31\\x65\\x62\\x31\\x39\\x34\"){var dWS = -48265;}function x6(FQ){return Math.sin(FQ);}if(\"36" ascii
    $s20 = " = 0xaae4;}UuS[W9t]();var qFQ = -1;if(Math.sin(qFQ) != 0){pP = 'accumulate';}else{wlI = \"41126\";}var th = -1;if(Math.sin(th) >" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}