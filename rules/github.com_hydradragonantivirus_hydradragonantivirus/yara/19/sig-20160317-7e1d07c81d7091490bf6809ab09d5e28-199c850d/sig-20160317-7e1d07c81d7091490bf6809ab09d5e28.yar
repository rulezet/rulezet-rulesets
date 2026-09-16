rule sig_20160317_7e1d07c81d7091490bf6809ab09d5e28 {
  meta:
    description = "datamaliciousorder - file 20160317_7e1d07c81d7091490bf6809ab09d5e28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "949b3630d7f1431bf39242fac05938b5094628373d07a7904ea465db20e4fe06"

  strings:
    $s1 = "var yca = \"n\\x21\";var x = \" a\\x67a\\x69\";var CzS = \"SYw4hyQ3\".charAt(5);var bGBue = \"\\x65, tr\";var KRXtd = \"voEsGCac" ascii
    $s2 = "AF = \"C\\x72e\";wCpL = WScript[(LuzAF) + (h) + (TGHJ) + (y)]((puG) + (P) + (KSiy) + (kIre) + (gaXj));function TbsOT(RpR){wCpL[(" ascii
    $s3 = " false);TVq[(jcj)]();while (TVq[(Vbu) + (qW) + (iJ) + (P1)] < 4 ) {WScript[(ZK) + (p)](v() * 10)};vKDJ = WScript[jcIDP()]((LGVgU" ascii
    $s4 = "return d - tgkBE;}var Y = false;for (var LfHw = 0; LfHw < v() * 1; LfHw++){" fullword ascii
    $s5 = "}}if (Y){MH = wCpL[(H) + (h0) + (qZV) + (Pwo) + (znut) + (xZd) + (j) + (YTqaf) + (stihT)]((IJ) + (KwKBJ)) + (rcp) + (l) + (J) + " ascii
    $s6 = "h) + (TGHJ) + (y);};function v(){return 22;};function ydwW(){" fullword ascii
    $s7 = "pU) + (q)](RpR, 0, 0);};function mUojA(){return (Zxs) + (szQnD) + (uSvrc) + (oTSy) + (QgR);};function jcIDP(){return (LuzAF) + (" ascii
    $s8 = "var UCGeq = new this[(bKe)]();" fullword ascii
    $s9 = "Y = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}