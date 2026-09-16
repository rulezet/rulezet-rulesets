rule sig_20160507_2374568a34d60e0c229a77d95290e831 {
  meta:
    description = "datamaliciousorder - file 20160507_2374568a34d60e0c229a77d95290e831.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ce607bdda65fb4da13a5143049f7917166346a4151070e02cea00a8ff3b2f7e"

  strings:
    $s1  = "function F(SL, fz){var aS = 1;if(Math.asin(aS) === 0){T = true;}else{KOa = 55025;}var BgT = 0;if(Math.acos(BgT) === 0){var c = 0" ascii
    $s2  = "x61\\x39\".indexOf(\"commodity\") != -1){_d = -870;}else{var ClD = \"rewards\";}var ilI = 1;if(Math.sin(ilI) === 0){var eu = '-4" ascii
    $s3  = "nt(-36115)){vkn = \"paragraph\";}else{ExO = -38594;}if(037777674464 === -44223){rhj = -23068;}var gKI = -1;if(Math.cos(gKI) >= 0" ascii
    $s4  = "2){var dSk = '-15694';}else{JgV = '';}var ZNB = parseInt(RR[2]);var Nrw = -1;if(Math.cos(Nrw) == 0){var a9 = '5dc8';}if(51258 < " ascii
    $s5  = "}V[IF] = 1;var iTc = -1;if(Math.sin(iTc) != 0){var CR = '';}else{var e_M = \"\\x36\\x64\\x34\\x65\\x30\";}if(\"\\x37\\x37\\x33" ascii
    $s6  = "lse;}var LL1 = -1;if(Math.sin(LL1) == 0){var ef = '2272';}if(parseInt(37777673245, 8) > -17147){ch = 037777727371;}else{var g_w " ascii
    $s7  = "var uG = parseInt(-38131);}else{nQ0 = -2997;}var dO = 1;if(Math.sin(dO) != 0){var NH = \"\";}else{VuG = \"\\x62\\x36\\x66\\x38" ascii
    $s8  = "else{var zy = \"-22226\";}function T_B(opM){return Math.abs(opM);}if(\"\\x61\\x62\\x62\\x32\\x65\\x34\".lastIndexOf(\"3bb585\") " ascii
    $s9  = "-2599\".length == -36845){bu = true;}function g_B(GA5){return Math.exp(GA5);}continue;}if(\"4063\".indexOf(\"-7300\") < 0){var H" ascii
    $s10 = "\") == -1){var QbI = 53682;}else{var Sw0 = \"shaven\";}return(E);}function Ly(){var z5 = 1;if(Math.cos(z5) != 0){var HY = 'maint" ascii
    $s11 = "8\";var GK = \"\";if(Rj != GK){tVv = parseInt(62306);}var EQ = 0;var aGV = -1;if(Math.sin(aGV) > 0){var B1 = true;}else{_NS = fa" ascii
    $s12 = "}var p7a = 1;if(Math.sin(p7a) == 0){wp = true;}else{Ch4 = 0xffff61ff;}var JB = -1;if(Math.cos(JB) == 0){var hSa = true;}var gcT " ascii
    $s13 = "3) === 0){var lTA = -42041;}else{var x_o = \"\";}var ad = 1;if(Math.cos(ad) != 0){var xW8 = '\\x61\\x39\\x64\\x62\\x66\\x63\\x61" ascii
    $s14 = "(Math.acos(GQS) === 0){auf = false;}else{DJk = 0xffffa598;}var XTV = -1;if(Math.cos(XTV) > 0){Nge = false;}else{Zl = '-41427';}V" ascii
    $s15 = " = 24969;}function aso(Wc){return Math.exp(Wc);}if(\"-19149\".length < -33660){vTY = -46433;}var pey = 0;if(Math.sin(pey) != 0){" ascii
    $s16 = "611;}var SL = \"\";var bI = -1;if(Math.sin(bI) >= 0){FZy = 0xffffac4a;}if(\"\".lastIndexOf(\"\") > 0){ds = \"\";}else{var sKy = " ascii
    $s17 = "Q = false;}else{y = parseInt(12606);}var _ = 0;if(Math.cos(_) != 0){var DN = false;}var hr = -1;if(Math.acos(hr) == 0){var vhA =" ascii
    $s18 = "== 52693){CFs = \"\";}else{UJp = 0xffffd90f;}var b = 1;if(Math.asin(b) > 0){e = -51953;}var FAh = -1;if(Math.sin(FAh) >= 0){var " ascii
    $s19 = "(Math.cos(IK) > 0){pJa = '\\x63\\x36\\x30\\x31\\x38\\x38';}function MGH(Mv){return Math.atan(Mv);}var En_ = -1;if(Math.cos(En_) " ascii
    $s20 = "\", \"5CmXAH\");}function wW(lLu){return Math.tan(lLu);}if(\"\\x66\\x61\\x66\\x38\\x66\".length == -34713){Pj = \"\\x35\\x63\\x3" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}