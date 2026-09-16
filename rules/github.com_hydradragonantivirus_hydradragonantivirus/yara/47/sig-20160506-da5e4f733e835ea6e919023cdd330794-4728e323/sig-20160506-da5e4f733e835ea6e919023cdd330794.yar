rule sig_20160506_da5e4f733e835ea6e919023cdd330794 {
  meta:
    description = "datamaliciousorder - file 20160506_da5e4f733e835ea6e919023cdd330794.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6d18d170402430b7af42ca6ede6a3cff1a593cf832243a1a21ce61a81889c4b"

  strings:
    $s1  = "function R(){if(\"\\x61\\x38\\x61\\x35\\x34\\x39\\x63\".lastIndexOf(\"colonnade\") != -1){AwJ = \"\\x35\\x64\\x35\\x66\\x62\\x38" ascii
    $s2  = "1;if(Math.asin(oD) > 0){var Gz = 0xffff80da;}function pW(O3Z){return Math.log(O3Z);}if(-23337 < parseInt(56651)){var yem = parse" ascii
    $s3  = "\\x38\\x33';}var jsy = -1;if(Math.cos(jsy) > 0){var XG = '8bed24e4';}var bPB = 1;if(Math.acos(bPB) == 0){XM = true;}if(\"\" != " ascii
    $s4  = "\\x31\\x38\\x30\\x36\\x34\\x64\\x36';}var P_c = -1;if(Math.cos(P_c) > 0){var PA = '26202';}else{duh = '\\x33\\x64\\x63\\x32';}if" ascii
    $s5  = "Ud) >= 0){var Kvh = true;}if(\"50063\".indexOf(\"-28504\") != -1){Itb = true;}var dQ = Math.floor(Math.random() * 65536);if(\"4" ascii
    $s6  = "G = -55118;}var Ep = -1;if(Math.acos(Ep) != 0){QVX = 037777602415;}var up = -1;if(Math.sin(up) >= 0){var jon = 0x85d;}else{var O" ascii
    $s7  = "th.acos(oO9) == 0){v8Y = false;}if(\"producers\".length > 5014){Aa = parseInt(23664, 8);}var QX = -1;if(Math.sin(QX) == 0){bO = " ascii
    $s8  = "if(\"-51318\".indexOf(\"6893\") == 0){SBK = true;}o[YuU] = 1;var lc = -1;if(Math.cos(lc) == 0){var OW = '';}if(0115321 == parseI" ascii
    $s9  = "Ll = 'religion';}var ajr = 1;if(Math.acos(ajr) == 0){var SZC = 0x7fd4;}var rj = 1;if(Math.cos(rj) === 0){var uxn = -38920;}else{" ascii
    $s10 = "s\") != -1){var mD = false;}else{blI = false;}var X4 = \"\";var BY = 1;if(Math.sin(BY) == 0){YL = \"-6646\";}else{var kLW = 'a2d" ascii
    $s11 = "= 0xfffffe43){var re = \"\";}function Z(sxe){return Math.abs(sxe);}var EFk = -1;if(Math.acos(EFk) != 0){yj7 = '-44724';}else{wbh" ascii
    $s12 = "1\\x36\\x38\\x66\\x37\".length === 0xa089){ceg = parseInt(44142);}function UxQ(vDa){return Math.exp(vDa);}var vFC = -1;if(Math.s" ascii
    $s13 = "exOf(\"f40438\") == -1){C4 = 'victorian';}var Et = 0;if(Math.cos(Et) === 0){var NCr = parseInt(24141);}else{var Tx = \"14034\";}" ascii
    $s14 = "= \"\\x31\\x64\\x61\\x32\\x30\\x36\\x39\\x36\";if(ThN === L0){var prY = '-26850';}var vjX = -1;if(Math.cos(vjX) == 0){gb2 = '-51" ascii
    $s15 = "e{var x = parseInt(37777651203, 8);}function ROd(D){return Math.abs(D);}var EXL = -1;if(Math.cos(EXL) >= 0){AHQ = \"9119\";}var " ascii
    $s16 = "00';}if(parseInt(-48585) >= parseInt(10035, 8)){var qHI = true;}else{rQT = \"\\x38\\x38\\x63\\x30\\x34\\x30\";}var EM = -1;if(Ma" ascii
    $s17 = "if(\"-40084\".length <= parseInt(45235)){esV = \"804a73df\";}var jC = -1;if(Math.sin(jC) > 0){bJY = '\\x61\\x33\\x36\\x64\\x32';" ascii
    $s18 = " nBi = 0;if(Math.cos(nBi) >= 0){var dI = \"9904\";}if(\"36115\".length < -39506){LPf = '44680b5';}function FS(KZ){return Math.ab" ascii
    $s19 = " false;}var C = 1;if(Math.sin(C) > 0){var BM = -13667;}else{UO = parseInt(-44052);}if(\"13eceab6\".length <= parseInt(78)){var O" ascii
    $s20 = "Dd = 0;if(Math.acos(MDd) > 0){WEE = \"-41646\";}sG = sG + 1;var fdL = 0;if(Math.sin(fdL) != 0){erD = \"\";}else{qT7 = 0xffffc223" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}