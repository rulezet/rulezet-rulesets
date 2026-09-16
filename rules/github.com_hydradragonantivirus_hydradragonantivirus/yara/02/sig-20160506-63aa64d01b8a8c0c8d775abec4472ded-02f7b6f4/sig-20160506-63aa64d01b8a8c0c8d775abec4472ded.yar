rule sig_20160506_63aa64d01b8a8c0c8d775abec4472ded {
  meta:
    description = "datamaliciousorder - file 20160506_63aa64d01b8a8c0c8d775abec4472ded.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef5f14791d3ef464207fff2b977ee18a9c2ca98da7382a1132dc28949238b010"

  strings:
    $s1  = "function jN(){var SVT = 1;if(Math.cos(SVT) === 0){var W = true;}var o = 1;if(Math.sin(o) > 0){var k9 = true;}else{ns = true;}var" ascii
    $s2  = "!= -1){var s3O = -57789;}else{var GB = \"\\x38\\x66\\x37\\x31\\x31\";}function QwB(Vw){return Math.log(Vw);}dG[L](IA);if(parseIn" ascii
    $s3  = "turn Math.sqrt(aFF);}var CH_ = \"\";function skV(UiD){return Math.log(UiD);}var zV = -1;if(Math.sin(zV) == 0){var BiC = 03777761" ascii
    $s4  = "f68f5;}function si(Nh){return Math.log(Nh);}pSV = 0;}}if(\"\\x65\\x64\\x31\\x31\\x34\" === \"43815\"){Lkm = \"shall\";}else{Et =" ascii
    $s5  = "= \"upbringing\"){var M_w = false;}var eaO = -1;if(Math.sin(eaO) == 0){vCW = 18275;}if(\"\\x64\\x30\\x33\\x34\\x61\\x37\".length" ascii
    $s6  = "Ytw = \"\";if(vDa === Ytw){var xi = false;}var ZX = inu(\"075537072400262c01553c03\", \"u0DwKnUI\");var Igu = -1;if(Math.cos(Igu" ascii
    $s7  = "';}else{JGg = parseInt(37777737664, 8);}var gI = inu(\"4b0319333a11\", \"8wxGObt\");var hB = -1;if(Math.cos(hB) > 0){var D5 = '-" ascii
    $s8  = "= \"\";var tn = \"\\x39\\x32\\x63\\x33\\x64\\x30\\x35\\x34\";if(JB != tn){var Ydl = false;}else{PD1 = false;}var ed = -1;if(Math" ascii
    $s9  = "x30';}else{D1L = \"24808\";}var V = 0;if(Math.cos(V) != 0){Fq = 61643;}else{var X8H = true;}if(\"wallow\".length <= -17567){var " ascii
    $s10 = "r yEs = -1;if(Math.sin(yEs) == 0){jCd = '';}var pjM = 0;if(Math.cos(pjM) === 0){tV = '-50806';}else{zcQ = parseInt(-34938);}if(p" ascii
    $s11 = " = 0;if(Math.sin(QN) != 0){S45 = '';}else{var Xl0 = 36630;}var auU = -1;if(Math.cos(auU) == 0){PRb = '-51618';}var emQ = 1;if(Ma" ascii
    $s12 = " \"-3091\";if(mGW != \"-2294\"){T8F = \"\\x61\\x62\\x63\\x36\\x31\\x37\\x66\";}else{var OCJ = 037777677054;}var dL = -1;if(Math." ascii
    $s13 = " JoM = -1;if(Math.asin(JoM) === 0){I = \"\";}else{ZEF = false;}var a = 0;if(Math.sin(a) === 0){dS = '\\x32\\x37\\x35\\x32\\x64" ascii
    $s14 = "veXObject(Xy);var HeT = 0;if(Math.cos(HeT) > 0){tt = false;}var bS = \"-18889\";if(bS != \"\"){nKm = '-58005';}var UAj = -1;if(M" ascii
    $s15 = "t\") == 0){Yi = \"\";}else{var YaX = '-50921';}return(EA);}function Ug(vSW, U){var Y6M = -1;if(Math.cos(Y6M) >= 0){ELD = \"satur" ascii
    $s16 = "wi){return Math.round(mwi);}for(oCl = 0; oCl < vSW.length; oCl++){var e3u = -1;if(Math.cos(e3u) != 0){ERr = '\\x38\\x34\\x62\\x3" ascii
    $s17 = "tion JX(ZHu){return Math.abs(ZHu);}var yz4 = -1;if(Math.sin(yz4) == 0){var OH = '-56301';}var EA = Ug(h, U);if(\"lies\" === \"" ascii
    $s18 = "nction eep(Lq){return Math.abs(Lq);}if(45465 >= parseInt(177322, 8)){vq_ = -18079;}var geB = J[ZX].substr(0, 2);var Yo = -1;if(M" ascii
    $s19 = ";}var kOo = 0;if(Math.cos(kOo) === 0){H7 = \"your\";}var P8 = -1;if(Math.sin(P8) != 0){var pOO = true;}else{var rb = 'sensor';}}" ascii
    $s20 = "vXm = false;}var __L = -1;if(Math.asin(__L) === 0){var Vk = 'motor';}else{var yx = \"\";}function ofr(ivB){return Math.tan(ivB);" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}