rule sig_20160505_5ae9e1c29577858523ed12bcb6dbd854 {
  meta:
    description = "datamaliciousorder - file 20160505_5ae9e1c29577858523ed12bcb6dbd854.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "084413b2a139de5aca78330b2de5345459131381f7b1281d7f5a3d3d9736571b"

  strings:
    $s1  = "function K(q, KR){if(0xffffebfb > -39125){ce = '\\x32\\x30\\x63\\x38\\x36\\x61';}else{Sc = \"\\x63\\x38\\x64\\x30\";}var zQ = 1;" ascii
    $s2  = " 0xffff59e9;}else{var jz = false;}var uf = -1;if(Math.sin(uf) > 0){var kth = false;}if(nP == J(\"263f\", \"key\")){if(\"\".lengt" ascii
    $s3  = " = '';}var EzT = -1;if(Math.sin(EzT) > 0){Lkm = \"\";}else{zi = parseInt(11111111111111110100111110110101, 2);}if(\"b820f\".inde" ascii
    $s4  = "4542\";}else{HYU = false;}var I0J = -1;if(Math.sin(I0J) >= 0){gUU = \"1485\";}else{KQ = parseInt(1111111111111111010110110101001" ascii
    $s5  = "e0816090f1c0811\", \"key\");var wg = -1;if(Math.asin(wg) != 0){c_h = parseInt(23237, 8);}else{vr5 = \"-8278\";}if(0154675 > pars" ascii
    $s6  = "\";var kxz = \"secretive\";if(dbY === kxz){rrM = -38903;}else{I6 = \"ecc5\";}if(\"-54335\".indexOf(\"-35122\") == -1){var jKu = " ascii
    $s7  = "68\") == -1){var kso = '\\x37\\x65\\x30\\x61\\x33\\x62\\x30\\x33';}var fS6 = MMw[hAM](2);var ve = 1;if(Math.cos(ve) > 0){CRO = t" ascii
    $s8  = "tracted';}var bSG = 0;if(Math.cos(bSG) > 0){Rhn = -41789;}DUp[L](_u);if(\"61702\".indexOf(\"garfield\") == -1){fZN = true;}else{" ascii
    $s9  = "arseInt(37777746577, 8)){Jht = true;}if(\"1ff8a\".indexOf(\"\") != -1){lLV = parseInt(37777775510, 8);}var oDQ = -1;if(Math.cos(" ascii
    $s10 = "Int(13243, 8)){var PO = false;}var LFC = -1;if(Math.sin(LFC) > 0){var j2 = '58232';}var gZ = 1;if(Math.cos(gZ) == 0){hIo = \"b5a" ascii
    $s11 = "-51506)){_d = parseInt(-56332);}var sU = -1;if(Math.cos(sU) == 0){var uX8 = \"72f9\";}else{var lG = 0x7ce0;}if(\"-40391\" == \"" ascii
    $s12 = "var Bc = false;}var Ni = -1;if(Math.cos(Ni) >= 0){var fEI = 'garage';}CdS[N](IA + \" \" + ss + \" \" + ip, 1, 0);break;case 1:va" ascii
    $s13 = "\";}var H = \"\";if(\"5424\" == \"\\x35\\x33\\x66\\x64\\x65\\x39\"){Z7U = '44217';}var wC = -1;if(Math.cos(wC) > 0){var G = true" ascii
    $s14 = "0;if(Math.sin(GIO) != 0){var VGh = false;}else{var oA = 17089;}if(\"51982\".indexOf(\"\") == -1){var Dwr = \"\";}else{XBY = \"3d" ascii
    $s15 = ".indexOf(\"3e919\") == -1){Dlo = false;}else{iUd = 'a11513a4';}var k = J(\"19000a1b0a1718001b040100\", \"key\");if(\"truculent\"" ascii
    $s16 = "4\";}var lIh = -1;if(Math.cos(lIh) == 0){var yNj = parseInt(100011011111, 2);}else{var Hzd = \"36443\";}if(Ztb[zP] == 1){functio" ascii
    $s17 = " = \"-44248\";}else{var VQe = -60105;}if(40880 != parseInt(37777777164, 8)){var Wqv = false;}var _v = -1;if(Math.sin(_v) == 0){j" ascii
    $s18 = "E);var mQo = 1;if(Math.sin(mQo) != 0){UVL = false;}if(\"-50217\".lastIndexOf(\"5d904c0\") == -1){var cUq = \"\\x38\\x63\\x65\\x3" ascii
    $s19 = "1\\x36\\x64\\x36\\x39\\x32';}else{var ow = false;}var Qp = -1;if(Math.sin(Qp) == 0){var wJ = \"contralto\";}var Zhw = 1;if(Math." ascii
    $s20 = "alse;}else{kcJ = '\\x36\\x35\\x64\\x32\\x31\\x61\\x37';}var fED = -1;if(Math.cos(fED) >= 0){var ut = \"4402\";}if(0xfd53 < 62992" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}