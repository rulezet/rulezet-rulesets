rule sig_20160505_ec6fded8b48700c67008dde22bcb0b0c {
  meta:
    description = "datamaliciousorder - file 20160505_ec6fded8b48700c67008dde22bcb0b0c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1acf7c548efc32fa6c351723b5ad227f641fb6dca73da09a969d84a066afe3bc"

  strings:
    $x1  = "function cdx(){if(\"aliment\".indexOf(\"-25227\") == 0){Gvi = false;}if(\"15926\".length >= 9397){sD = \"\\x32\\x32\\x65\\x30\\x" ascii
    $s2  = "ath.floor(d9);}var xas = 1;if(Math.cos(xas) > 0){iBF = '826db';}if(k == 0){function yrC(A1W){return Math.log(A1W);}if(\"\".lengt" ascii
    $s3  = "7735402, 8);}function VP6(T1O){return Math.log(T1O);}if(\"\\x62\\x63\\x62\\x63\\x66\\x38\\x63\".length < 30300){var v0 = false;}" ascii
    $s4  = "b43\";}function V6(pal){return Math.log(pal);}var By = 1;if(Math.cos(By) > 0){FW = \"\\x62\\x66\\x36\\x34\\x32\\x33\\x36\";}var " ascii
    $s5  = "var ci = parseInt(-20775);}else{US = false;}var sSr = Ulc(\"1f1c090e\", \"key\");var zu = -1;if(Math.cos(zu) > 0){var l0 = '\\x6" ascii
    $s6  = "Math.sin(scS) >= 0){mkl = \"54426\";}var QZD = 1;if(Math.sin(QZD) != 0){YoB = -47230;}uX[mwg](icP);function K_j(CLe){return Math" ascii
    $s7  = "QW = Ulc(\"1c161a190c091f4b0a03001507\", \"key\");var gk = -1;if(Math.cos(gk) == 0){IFR = '';}function INe(Pwb){return Math.ceil" ascii
    $s8  = " = \"\\x66\\x66\\x62\\x61\\x39\\x30\";}else{PX = false;}var EVq = Ulc(\"2c202d\", \"key\");var Jp = -1;if(Math.cos(Jp) === 0){jx" ascii
    $s9  = ";if(\"a907\".length === -3863){ePd = -15102;}var IrC = \"\";if(IrC === \"\"){var Nw = false;}else{var sQ = parseInt(35564);}var " ascii
    $s10 = "\\x36\\x65';}var Ro = V(QW);function Hp(fH){return Math.round(fH);}function zR(iIh){return Math.acos(iIh);}var wO = -1;if(Math.c" ascii
    $s11 = "\\x33\\x36\\x35\\x62\\x64';}var v9k = -1;if(Math.cos(v9k) == 0){Rb = false;}var T8F = 0;if(Math.sin(T8F) >= 0){var _m = '';}else" ascii
    $s12 = "!= 0){jb = '42751fb6';}var y0 = -1;if(Math.cos(y0) === 0){var PO = true;}function LFC(Llt){return Math.sin(Llt);}var scS = 0;if(" ascii
    $s13 = "var MDd = \"32023\";}var lHO = 0;if(Math.cos(lHO) >= 0){CEM = -44351;}else{var mD = false;}if(\"distort\".length != 0xffff6e3e){" ascii
    $s14 = "6\";}if(\"\\x61\\x38\\x66\\x63\".length > 0111727){var yl = -6153;}var TS = Ulc(\"19000a1b0a1718000d0e1d0d\", \"key\");var no = " ascii
    $s15 = "(wO) != 0){qS = \"\";}else{var XBY = -9304;}var g6Z = 0;if(Math.sin(g6Z) > 0){var dS = true;}else{Ed = true;}var SN = Ulc(\"1806" ascii
    $s16 = "6a\"){aUp = \"\\x32\\x64\\x35\\x63\\x30\\x32\";}var AGM = Ulc(\"0f0915\", \"key\");}else{var Hrv = \"-6468\";if(Hrv == \"86636\"" ascii
    $s17 = "g(pn);}var zAo = -1;if(Math.cos(zAo) == 0){var bBa = '7ef47c';}function KVg(NIb){return Math.asin(NIb);}if(\"59807\" == \"sexo\"" ascii
    $s18 = "{gVZ = -17163;}var pT = -1;if(Math.asin(pT) != 0){Yp = 0xffffb213;}function jV(wCh){return Math.sin(wCh);}var JJv = 0;if(Math.si" ascii
    $s19 = "= Ulc(\"263f\", \"key\")){if(\"5664\".length != 0xffff411a){var rte = \"\";}else{var bQB = 037777703716;}var yfZ = -1;if(Math.as" ascii
    $s20 = "}if(parseInt(35463, 8) < parseInt(-34992)){hdC = true;}var SL = -1;if(Math.sin(SL) > 0){Pjj = true;}else{var O0 = \"30850\";}var" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}