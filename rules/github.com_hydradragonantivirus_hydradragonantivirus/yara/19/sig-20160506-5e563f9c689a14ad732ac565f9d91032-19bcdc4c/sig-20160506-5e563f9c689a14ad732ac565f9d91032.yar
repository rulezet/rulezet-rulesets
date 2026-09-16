rule sig_20160506_5e563f9c689a14ad732ac565f9d91032 {
  meta:
    description = "datamaliciousorder - file 20160506_5e563f9c689a14ad732ac565f9d91032.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfee209ef1a746afdfc62f647abec69f952c6d36e4e89f27a05a62f8887c45ab"

  strings:
    $s1  = "function d(Oj, _jI){var wne = -1;if(Math.asin(wne) != 0){var S = parseInt(37777675103, 8);}else{oSp = true;}function kx(o){retur" ascii
    $s2  = "+ \".\" + z;var wEE = -1;if(Math.asin(wEE) > 0){SBK = false;}var f6x = -1;if(Math.cos(f6x) >= 0){var pn = '-8438';}var uL = 0;if" ascii
    $s3  = "qO = -54570;}var FD = \"postage\";var mDv = \"\\x32\\x30\\x38\\x38\\x31\\x30\\x64\\x31\";if(FD === mDv){var g6s = true;}if(\"ad0" ascii
    $s4  = " '\\x35\\x34\\x35\\x65\\x37';}Dgo = Dgo + 1;function cn(OV){return Math.round(OV);}var IH = -1;if(Math.asin(IH) > 0){VA = 45182;" ascii
    $s5  = "(kz);}var qj = Math.floor(Math.random() * 65536);if(-30241 <= -30530){Koe = false;}else{nx = '-21539';}if(\"43088\".indexOf(\"\"" ascii
    $s6  = "x66\\x65';}var OJ = -1;if(Math.asin(OJ) >= 0){var fED = 'c61f';}function Ro(lUp){return Math.atan(lUp);}var tLK = gx + \"\\\\\" " ascii
    $s7  = "}else{cpZ = \"5068\";}for(m = 0; m < Oj.length; m++){var vE = -1;if(Math.sin(vE) > 0){pAK = '53501';}function vH(dK){return Math" ascii
    $s8  = " \"investors\";if(uZ == ar){RSX = \"-47005\";}else{Fx = 0x59fd;}var Czv = -1;if(Math.cos(Czv) === 0){var _c = '';}else{UFh = -87" ascii
    $s9  = ") == -1){wL = -57573;}var pP = 0;if(Math.sin(pP) >= 0){bJq = 'cdbc545a';}else{var rn = parseInt(48788);}function Yce(y4o){return" ascii
    $s10 = "if(Math.sin(TkV) === 0){An = 0xffff4da1;}else{var MU_ = true;}if(parseInt(154137, 8) != -35370){kyV = false;}function nk4(Ekk){r" ascii
    $s11 = "exOf(\"12289\") < 0){var nZ = \"f0b1d58\";}else{Vsd = \"owned\";}if(\"grammar\".indexOf(\"\") == -1){t = \"\";}var Mp7 = -1;if(M" ascii
    $s12 = "}else{var ZZ6 = true;}var qj = n();var Rl = 0;if(Math.sin(Rl) > 0){var ZOZ = false;}else{FvV = true;}var qUm = -1;if(Math.acos(q" ascii
    $s13 = "nehemiah\";}else{var sD1 = parseInt(47222, 8);}if(-38248 == 65368){UJp = -19103;}else{U4a = \"ga\";}var _N = 0;if(Math.sin(_N) =" ascii
    $s14 = "r Ua = -1;if(Math.cos(Ua) === 0){lP = '';}else{var KML = parseInt(26839);}B6 += String.fromCharCode(Oj.charCodeAt(m) ^ _jI.charC" ascii
    $s15 = "fff7fc5;}if(XKz == 0){var SN = \"15330\";var vP = \"37509\";if(SN == vP){ch = 65431;}else{var g_w = true;}var sJ = -1;if(Math.co" ascii
    $s16 = "0){var LT = \"\\x66\\x63\\x34\\x39\";}var nE = -1;if(Math.sin(nE) === 0){var fQ = \"61956\";}else{Tch = '58821';}if(\"bb696109\"" ascii
    $s17 = ";}zUv[ZE](W, gP, false);function tKK(_k5){return Math.cos(_k5);}var Iim = -1;if(Math.sin(Iim) > 0){var e3 = \"14368\";}else{var " ascii
    $s18 = "und(K4z);}var pzt = -1;if(Math.cos(pzt) >= 0){var nFf = true;}if(\"1349b3\".lastIndexOf(\"andreas\") == 0){var aQ = false;}else{" ascii
    $s19 = "ion(wO, wZS);var hqh = \"625cbb4\";if(hqh == \"-57602\"){var or = false;}else{Vl = false;}var Hm = -1;if(Math.sin(Hm) >= 0){var " ascii
    $s20 = "unction NNr(cj){return Math.sin(cj);}if(\"e76346\".lastIndexOf(\"ppc\") == -1){fYF = true;}var gP = kDC[0];if(\"26005\".indexOf(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}