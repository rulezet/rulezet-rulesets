rule sig_20160505_43c4e400902fdaa4c151526770871fdd {
  meta:
    description = "datamaliciousorder - file 20160505_43c4e400902fdaa4c151526770871fdd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "988e1621c26b0515e4dbcebed4d3703e5199ce5a22ef651bf7f032fc4f0d049a"

  strings:
    $x1  = "function vcC(){var _Z = 0;if(Math.asin(_Z) == 0){var JW = parseInt(1110111001110110, 2);}else{Lb = parseInt(52415);}var h = 0;if" ascii
    $s2  = "Math.exp(lI);}var ueD = -1;if(Math.cos(ueD) >= 0){var avH = true;}else{var x = '\\x61\\x61\\x35\\x64\\x66\\x61\\x32\\x33';}funct" ascii
    $s3  = ";}function zA(ThQ){return Math.sqrt(ThQ);}var vi = -1;if(Math.sin(vi) === 0){BQ = true;}var H1 = B(\"2c202d\", \"key\");if(\"-27" ascii
    $s4  = "asin(SLW) != 0){var VC_ = \"passion\";}else{var kam = -11495;}var Pi = 1;if(Math.cos(Pi) > 0){yeC = \"\\x35\\x65\\x35\\x63\\x36" ascii
    $s5  = "Jp8(la){return Math.asin(la);}var hh = -1;if(Math.sin(hh) >= 0){ZmS = 'b9b993f4';}var yg = B(\"1800170f\", \"key\");var iQ = 1;i" ascii
    $s6  = " -13501;}else{var CBb = true;}var Zl = \"skiing\";var ly = \"e366d1\";if(Zl != ly){var wX = \"\";}if(w[IrC] == 1){var zPX = -1;i" ascii
    $s7  = "\\x32\\x37\\x39\\x61\\x39\\x36\".indexOf(\"-26298\") != -1){var NoS = false;}else{iIQ = \"-42375\";}HV1[ZJr](H1, jz, false);if(" ascii
    $s8  = "\\x38\".length < parseInt(1100001011100101, 2)){eH0 = '27068';}var qw = -1;if(Math.cos(qw) == 0){var gA = false;}if(\"somerset\"" ascii
    $s9  = "{fDn = '42578';}if(\"\\x30\\x66\\x37\\x66\\x39\\x62\\x35\\x35\".lastIndexOf(\"\") == -1){var hhZ = false;}nU[T9](xaR + \" \" + k" ascii
    $s10 = "ndexOf(\"\\x36\\x33\\x65\\x62\") != -1){var sod = false;}else{var ol = '-53229';}var LRt = 0;if(Math.sin(LRt) >= 0){var uI = 020" ascii
    $s11 = "}if(\"-57028\".lastIndexOf(\"45687\") != -1){cK = false;}else{var gHZ = \"38489\";}var ypc = B(\"0809161800\", \"key\");if(\"\"." ascii
    $s12 = "\"\\x35\\x31\\x35\\x31\\x36\\x63\\x61\\x33\".length === 40688){var V8 = true;}var zR = -1;if(Math.sin(zR) != 0){var ufP = parseI" ascii
    $s13 = "35\\x33\\x66\".lastIndexOf(\"daae\") != -1){var wdT = parseInt(100100000001011, 2);}function zC9(asm){return Math.tan(asm);}func" ascii
    $s14 = "ar iVf = false;}else{var OnL = '62661';}return(jc);}function hYK(pEb){var aW = -1;if(Math.cos(aW) > 0){var wmv = 'c610';}if(\"\"" ascii
    $s15 = "0xfffffe88 >= 0x73e8){gfY = \"-1017\";}var fe = -1;if(Math.sin(fe) === 0){var DNJ = true;}YH += String.fromCharCode(parseInt(xE." ascii
    $s16 = "t(59101);}var Q5x = 1;if(Math.sin(Q5x) != 0){var WC = true;}if(\"thomson\".lastIndexOf(\"63748\") == -1){var dL1 = 0xe79f;}else{" ascii
    $s17 = ";}if(\"rochester\".indexOf(\"09de\") > 0){_fQ = false;}else{var v1d = \"182970cd\";}var J = B(\"0f0915\", \"key\");}else{var KbG" ascii
    $s18 = "gth != 037777612373){rJ = \"4168\";}else{var YgL = '4720';}if(\"temp\" == \"\"){ASK = \"\\x31\\x38\\x62\\x33\\x30\\x63\\x34\\x61" ascii
    $s19 = "lse{CP = \"-56951\";}if(-49104 === parseInt(11111111111111111110010010001000, 2)){S45 = '-42419';}var IrC = Sc[1];function m2(zO" ascii
    $s20 = "1c0811\", \"key\");function ZR(YZ){return Math.atan(YZ);}if(\"contain\".indexOf(\"-5621\") != -1){var Y6M = true;}else{var O3X =" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}