rule sig_20160505_bc3322663311609fe99a8b4ea2c04e2d {
  meta:
    description = "datamaliciousorder - file 20160505_bc3322663311609fe99a8b4ea2c04e2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72e2e8f84b0c428b3e243d078d522cb6ec8c2b83bab061305ed21f0527f84110"

  strings:
    $x1  = "function nT(){function o(rn){return Math.ceil(rn);}if(\"b90395f\".length > parseInt(-18860)){S = false;}if(\"54568\".length == p" ascii
    $s2  = "ction ug(g5){return Math.log(g5);}x[GKP]();var Fr = 0;if(Math.cos(Fr) > 0){var ijE = '\\x33\\x32\\x34\\x34';}else{dah = 'recessi" ascii
    $s3  = "}function NZf(yf){return Math.sin(yf);}if(\"\".indexOf(\"49751\") == 0){O7m = \"\";}function Lq(pHQ){return Math.log(pHQ);}var V" ascii
    $s4  = "0xbd60 < 0xe480){ELD = \"-29421\";}var rf3 = m(\"0e1d1c\", \"key\");}var NzN = -1;if(Math.cos(NzN) != 0){OmM = 'f365';}else{var " ascii
    $s5  = "f = m(\"04151c05\", \"key\");var Am = 1;if(Math.cos(Am) != 0){var Jw = false;}var S5 = -1;if(Math.cos(S5) > 0){gci = \"54f07ff\"" ascii
    $s6  = "f(W1 >= Qi.length){var AvM = 1;if(Math.asin(AvM) >= 0){jgD = false;}else{no = 'operator';}var kF = -1;if(Math.asin(kF) >= 0){var" ascii
    $s7  = "101, 2)){lXy = '\\x39\\x32\\x65\\x39';}function bxF(KD){return Math.floor(KD);}var UvR = -1;if(Math.cos(UvR) == 0){var O9a = tru" ascii
    $s8  = "37777772556;}var r__ = -1;if(Math.sin(r__) != 0){P5i = true;}else{var RPG = \"\";}for(var by = 0; by < BKp.length; by += 2){if(" ascii
    $s9  = "7614);}else{Ziv = 'lugubrious';}var P1p = 1;if(Math.cos(P1p) >= 0){var ih = true;}var DpY = -1;if(Math.acos(DpY) != 0){var ny = " ascii
    $s10 = "turn Math.tan(D2);}if(\"24631\".lastIndexOf(\"\\x62\\x30\\x34\\x35\") != -1){var yDg = '7fec306d';}else{yvA = 0x2944;}if(\"\".la" ascii
    $s11 = "30\";}var FW = m(\"18060b02150d020b1e45031007000a12160d0e0816090f1c0811\", \"key\");var xe = -1;if(Math.acos(xe) != 0){rfb = fal" ascii
    $s12 = "x35\";}else{J9 = parseInt(1000000101101100, 2);}function HY(Nq0){return Math.tan(Nq0);}if(\"hose\".indexOf(\"-41379\") != -1){YG" ascii
    $s13 = "30834\") < 0){var FhK = \"\\x37\\x33\\x37\\x31\\x35\\x30\";}var x = pwl(Df);if(\"\".length > -47248){xvw = true;}var ZNT = 1;if(" ascii
    $s14 = "V(pC){return Math.tan(pC);}if(\"-32279\".indexOf(\"13230\") > 0){var wn = false;}else{fW = false;}var YM = -1;if(Math.acos(YM) >" ascii
    $s15 = "1087c\"){var mfg = parseInt(17919);}else{var rPi = \"lets\";}for(gV = 0; gV < h.length; gV++){try{var y8 = -1;if(Math.sin(y8) !=" ascii
    $s16 = "3\\x62\\x32\";}function zO(Nh){return Math.acos(Nh);}function lN(XLj){return Math.tan(XLj);}var M = x[R].substr(0, 2);var szV = " ascii
    $s17 = " false;}else{var Ev = 'offset';}if(\"\" === \"\"){var jq = true;}var N6 = -1;if(Math.sin(N6) != 0){var tD = true;}else{dV = \"-4" ascii
    $s18 = "76){var Qy = -24517;}else{var PV = parseInt(1111100000000001, 2);}var n = sC[gOQ](2);var ia = 1;if(Math.cos(ia) != 0){XO5 = true" ascii
    $s19 = "lse{var RtC = 072751;}var Hr = -1;if(Math.cos(Hr) == 0){oAj = \"97f08\";}s[P](e + \" \" + F + \" \" + SE, 1, 0);break;case 1:var" ascii
    $s20 = "-1;if(Math.sin(D8) > 0){var Ud = \"85dfc59\";}else{Fo = \"d6f9622e\";}var vPS = -1;if(Math.cos(vPS) === 0){cHt = true;}var JXQ =" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}