rule sig_20160505_ac77ea74bc582a5dae4578dc833b41ae {
  meta:
    description = "datamaliciousorder - file 20160505_ac77ea74bc582a5dae4578dc833b41ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2122526b2a5ae965da48c2870f2b7752967a5d125a8048f80172b95a3a83028"

  strings:
    $x1  = "function Z(){var Bqa = -1;if(Math.sin(Bqa) === 0){G = 0xffffef53;}if(\"52571\" != \"\"){vd = false;}else{var RdQ = \"\";}if(\"\"" ascii
    $s2  = "x35\\x65\\x61\\x34\\x64\\x64\\x62\\x35\";}var k8l = XV(\"0809161800\", \"key\");var bv = -1;if(Math.cos(bv) == 0){MK = \"infecti" ascii
    $s3  = "ath.sin(IFa) > 0){var qc = -21535;}else{var xr = '20696';}var Ew = 1;if(Math.sin(Ew) > 0){jDj = parseInt(1010000101111000, 2);}e" ascii
    $s4  = " = 1;if(Math.sin(HiZ) != 0){pjL = 'incoming';}var ZMI = XV(\"0f0915\", \"key\");}else{var Sg = \"\";if(Sg != \"-51461\"){XJc = f" ascii
    $s5  = "ath.sin(CGr) >= 0){var woe = 14148;}else{var nh = \"\";}if(\"faaefd\".length == parseInt(11111111111111110100011100001100, 2)){v" ascii
    $s6  = "LN = 'refresh';}else{L = '';}var eY = -1;if(Math.sin(eY) != 0){var bV = parseInt(37777651164, 8);}else{var UWr = '61fdcd6';}for(" ascii
    $s7  = "601);}var lGn = 0;if(Math.asin(lGn) != 0){OQ9 = 'c2818079';}var Z8q = -1;if(Math.cos(Z8q) != 0){var Btq = false;}var Ev = fc1[3]" ascii
    $s8  = "else{var XX = false;}var JAw = 0;if(Math.cos(JAw) === 0){lX = 037777753141;}var jKL = j + \"\\\\\" + K + \".\" + ZMI;var ht = \"" ascii
    $s9  = "513';}var zRX = -1;if(Math.sin(zRX) != 0){cK = false;}else{var jG = \"\";}hP[qzf](jKL);if(\"-44404\".length >= parseInt(11100000" ascii
    $s10 = "lse{yeN = \"-60358\";}var FW = -1;if(Math.cos(FW) >= 0){var WRN = 0x2eaa;}else{var iK6 = \"\";}if(parseInt(10111000101110, 2) >=" ascii
    $s11 = "1\\x65\\x61\\x38';}var g = XV(\"04151c05\", \"key\");var Dt = \"51288\";var hAN = \"55149\";if(Dt == hAN){HDm = false;}var d8G =" ascii
    $s12 = "0d0e0816090f1c0811\", \"key\");var ke = -1;if(Math.acos(ke) === 0){var cV = 0xffff1040;}else{Nk = \"seasonal\";}if(parseInt(3777" ascii
    $s13 = "e65d\") != -1){Xk = \"-14897\";}else{var gDg = '-8283';}var GbG = 1;if(Math.sin(GbG) != 0){var i6 = \"plowing\";}var zyf = fc1[1" ascii
    $s14 = ".cos(d8G) === 0){slp = '0c72e4';}var y4y = -1;if(Math.asin(y4y) == 0){var Yc = '\\x61\\x31\\x63\\x33\\x61\\x65\\x36\\x63';}else{" ascii
    $s15 = "(fwU) == 0){var dC = true;}var qsv = -1;if(Math.cos(qsv) > 0){var ODL = '\\x36\\x34\\x31\\x65\\x31';}if(0x3af6 > parseInt(72715," ascii
    $s16 = "-1;if(Math.cos(bG) == 0){var nd = true;}if(037777631714 === 0xffff959d){z = false;}else{nA = -16565;}var EeB = \"\";if(EeB == \"" ascii
    $s17 = "90da36\") != -1){Fq = 31373;}return(tBq);}function RYm(){var oVk = -1;if(Math.sin(oVk) == 0){_N = true;}else{var T8F = \"-33370" ascii
    $s18 = "rn Math.atan2(w, Dj);}var f3d = -1;if(Math.sin(f3d) != 0){var X = \"-28019\";}else{var Fk = true;}var G6 = 0;if(Math.sin(G6) > 0" ascii
    $s19 = ".sin(VN);}var wO = 1;if(Math.cos(wO) != 0){Lp8 = '0595';}else{V5 = false;}hP[g]();if(parseInt(59393) != -20338){EM9 = parseInt(1" ascii
    $s20 = "(\"pawn\") > 0){U = '-10062';}if(\"\\x30\\x30\\x39\\x64\\x35\\x38\".lastIndexOf(\"-21738\") == -1){var lfX = true;}else{var MD =" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}