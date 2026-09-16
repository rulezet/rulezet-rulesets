rule sig_20160506_b108cf2a981e8990ca5d331f91d6062e {
  meta:
    description = "datamaliciousorder - file 20160506_b108cf2a981e8990ca5d331f91d6062e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80e8e7f6e20314a9c1113588df99c921fd48d1ca06e553823b2c3007ec67524c"

  strings:
    $x1  = "function T(yH, I5Y){var nG = \"building\";if(nG === \"44400\"){var qz = \"\\x32\\x30\\x63\\x32\\x35\\x65\\x34\\x64\";}var ZzM = " ascii
    $s2  = "ace';}if(\"\\x33\\x39\\x34\\x38\\x37\\x33\" != \"-3118\"){var XU6 = \"27287\";}else{ma_ = \"240d0\";}function L0c(ODL){return Ma" ascii
    $s3  = "n Math.log(Ox);}switch(djt){case 0:if(-45457 < parseInt(12127)){q3 = -26319;}else{var Fkc = false;}if(\"-36105\" === \"\\x61\\x3" ascii
    $s4  = " = -7675;}else{var bq = 'compost';}if(\"\".length < 12722){var p2Q = 037777766421;}function YvV(ru, lv){return Math.atan2(ru, lv" ascii
    $s5  = " parseInt(61227);}else{phI = 'cp';}var dN = -1;if(Math.sin(dN) == 0){lll = true;}if(\"appreciate\".lastIndexOf(\"committee\") > " ascii
    $s6  = "= 0){kf = true;}else{var ce2 = \"27907\";}nyG = nyG + 1;if(\"sid\".lastIndexOf(\"2659\") != -1){gl = \"\\x63\\x63\\x30\\x39\\x31" ascii
    $s7  = "\\x36\";}else{BIR = true;}var mGW = \"935e\";if(mGW != \"\"){T8F = \"\";}else{var OCJ = parseInt(-25016);}var dL = -1;if(Math.co" ascii
    $s8  = " Math.tan(HeT);}continue;}if(\"mood\".lastIndexOf(\"59765\") != -1){var _5h = \"-33474\";}else{ELD = \"62b2\";}if(\"-42960\".len" ascii
    $s9  = "indexOf(\"e92288\") != -1){IPz = false;}var xW = 0;if(Math.sin(xW) >= 0){HZ = true;}else{var Rfx = \"b757aa\";}if(0xffffe71d < 5" ascii
    $s10 = " true;}else{Ch4 = -60219;}var JB = 1;if(Math.sin(JB) > 0){var waE = true;}else{bta = true;}var ed = \"\\x62\\x35\\x37\\x65\\x36" ascii
    $s11 = "= false;}var yv = -1;if(Math.acos(yv) === 0){_w = true;}var zbW = 1;if(Math.cos(zbW) == 0){var ExO = \"-33283\";}if(\"50548\" ==" ascii
    $s12 = "(\"49de010b\".indexOf(\"\") == -1){vPS = true;}else{var Fe = \"25157\";}function SdP(XV){return Math.cos(XV);}function lIh(HeT){" ascii
    $s13 = "{var UIP = true;}var h = -1;if(Math.cos(h) == 0){var ZG = '-8062';}var nec = 1;if(Math.acos(nec) > 0){cYI = 59382;}var P6 = -1;i" ascii
    $s14 = " = 15406;}else{var HGL = '\\x31\\x31\\x33\\x35\\x32\\x33';}var Mp7 = -1;if(Math.sin(Mp7) === 0){ms6 = parseInt(54761, 8);}return" ascii
    $s15 = "v = '';}else{var ktD = 25722;}if(\"-28347\".lastIndexOf(\"47673\") != -1){var c5w = 21263;}if(\"\\x39\\x65\\x33\\x39\\x62\\x34" ascii
    $s16 = "59 = 0;if(Math.cos(a59) == 0){var Daq = 'three-quarter';}var NwP = -1;if(Math.asin(NwP) === 0){var MAc = 'finger';}else{var ykj " ascii
    $s17 = "\"\";}else{var Lr = 487;}var Fs = 0;if(Math.cos(Fs) > 0){var _I2 = false;}if(\"a28477d\".length != -35251){var aL = 'marion';}el" ascii
    $s18 = "e8cf;}if(\"fbe6d597\".indexOf(\"lions\") < 0){rw = false;}else{var pAd = \"\\x30\\x36\\x64\\x65\\x35\\x62\\x34\";}var XTV = -1;i" ascii
    $s19 = "t(2427) <= 51714){var sI = '\\x63\\x66\\x35\\x31\\x33\\x39';}else{v2d = '-27899';}var HH = -1;if(Math.cos(HH) != 0){var fEI = '5" ascii
    $s20 = "in(CLe) >= 0){qOr = false;}else{chC = true;}xG3[ZIG]();var piN = -1;if(Math.cos(piN) >= 0){var ftq = parseInt(50225);}if(parseIn" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}