rule sig_20160505_8b6cec2760baeb649d75ad3a081fbd1e {
  meta:
    description = "datamaliciousorder - file 20160505_8b6cec2760baeb649d75ad3a081fbd1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8133a1a8e016318e3b364f32908a23762fe3e274894fcb87462b8aedf74506f6"

  strings:
    $x1  = "function Pw(JTF, jI){var FtR = 0;if(Math.sin(FtR) === 0){uh = \"26488\";}if(\"17347\".indexOf(\"newark\") > 0){var r3F = false;}" ascii
    $s2  = "p){gk = '';}else{var myd = parseInt(28582);}var lUp = YZa(\"0a01160f075718110b0e0414\", \"key\");function hHR(Sps){return Math.l" ascii
    $s3  = "ue;}function Mp7(yXj){return Math.log(yXj);}if(\"-4486\".indexOf(\"\\x63\\x63\\x31\\x38\\x30\") > 0){var ijE = '\\x32\\x64\\x35" ascii
    $s4  = " = WdL + 1;var uC = -1;if(Math.sin(uC) == 0){var fVk = false;}else{var AS = '\\x33\\x65\\x61\\x65';}var d = 0;if(Math.cos(d) ===" ascii
    $s5  = "Math.sin(yog) >= 0){var W_J = \"5246\";}var vYF = -1;if(Math.cos(vYF) != 0){Ns = 'clinic';}else{var Vq3 = 0x4d2d;}var oje = 0;if" ascii
    $s6  = "ath.asin(oje) != 0){ZGN = false;}var TS = YZa(\"0f0915\", \"key\");}else{var Eg = -1;if(Math.acos(Eg) != 0){var MC = false;}var " ascii
    $s7  = " == 0){fW = 0115177;}var Mj = YZa(\"191017\", \"key\");function gVW(Vs){return Math.exp(Vs);}var aXr = -1;if(Math.acos(aXr) === " ascii
    $s8  = "se{GPd = true;}if(\"-61421\".lastIndexOf(\"bridget\") < 0){var Ab = 'adapt';}if(\"56424\".lastIndexOf(\"limbo\") == -1){aO = par" ascii
    $s9  = "010110, 2);}var sSr = YZa(\"0c000d18151c080c1807031607011c19\", \"key\");var GMg = 1;if(Math.cos(GMg) >= 0){O2 = true;}var yN = " ascii
    $s10 = "x32\\x31\") == -1){var TC = true;}var Vx = 1;if(Math.cos(Vx) === 0){var NPu = true;}else{var ErN = 'bunsen';}var LBq = \"\";if(L" ascii
    $s11 = "{P5 = \"\";}var VZ = 0;if(Math.sin(VZ) > 0){var MDX = \"-43746\";}else{var LfZ = -49361;}}}}function G(Nr){var Zr = -1;if(Math.c" ascii
    $s12 = "(Math.cos(yN) >= 0){var evN = true;}else{var ty = '';}if(\"26689\".length >= -21497){var dFN = '\\x64\\x62\\x61\\x38\\x34';}if(" ascii
    $s13 = " 0;if(Math.cos(s_) != 0){dr = \"882e\";}if(parseInt(-25780) > parseInt(-7719)){iw = -56879;}else{var joR = true;}if(parseInt(110" ascii
    $s14 = "(Math.cos(wb) > 0){Z9 = '58639';}else{var ms6 = -40781;}if(2764 >= -50219){pTG = true;}else{cz = '43657';}if(\"40824\".lastIndex" ascii
    $s15 = " TF = -1;if(Math.cos(TF) === 0){c3F = \"ea159dc\";}else{veY = 9809;}if(\"houseboat\".indexOf(\"59657\") > 0){var FcL = '1884';}e" ascii
    $s16 = "01011110, 2);}else{var y7 = true;}var SI = -1;if(Math.sin(SI) === 0){oo = '-62312';}else{var bj = false;}Is[EVq] = 1;var aNq = -" ascii
    $s17 = "prefect\".lastIndexOf(\"\") != -1){vPL = false;}else{Oa = '';}var FY = 0;if(Math.cos(FY) >= 0){Pp = '\\x62\\x38\\x62\\x37\\x32" ascii
    $s18 = "se{var y2 = \"\";}if(\"33455\" != \"94a73\"){p2 = 'crag';}else{var AX9 = parseInt(37777757554, 8);}var W6y = -1;if(Math.sin(W6y)" ascii
    $s19 = "e{hT = \"9b2bc9\";}if(\"\".length < parseInt(174365, 8)){var Mh = true;}else{var puc = 0x974f;}var T0 = G(r);var Bz = -1;if(Math" ascii
    $s20 = "var tkW = -49902;}var Oj = -1;if(Math.cos(Oj) > 0){var dQ = false;}else{var mm = 58326;}if(WdL >= mkt.length){var tU = 1;if(Math" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}