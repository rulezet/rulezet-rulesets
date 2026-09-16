rule sig_20160506_ddfc42af8936b6a3f84de9d651500567 {
  meta:
    description = "datamaliciousorder - file 20160506_ddfc42af8936b6a3f84de9d651500567.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55113835d23bfb950f0a313826187b0465b508b7196615d44fb6b9265f90a430"

  strings:
    $x1  = "function gD(y, CC){if(-57117 != 28977){var rv = \"9140\";}var ItN = \"746f\";if(ItN != \"6778\"){YCL = \"\\x35\\x35\\x35\\x39\\x" ascii
    $s2  = " == -1){FCe = \"52838\";}else{vY = parseInt(60031, 8);}o[ilI] = 1;}}}catch(p){function UF8(w5){return Math.log(w5);}if(\"-50438" ascii
    $s3  = ".round(v_);}var b5i = 1;if(Math.sin(b5i) == 0){ft = 'whore';}ETT[l](V4y, 1, 0);break;}function HT(zsL){return Math.log(zsL);}fun" ascii
    $s4  = "turn Math.atan(UFh);}if(\"\".indexOf(\"da909fc\") != -1){var Gz = -56134;}else{bU = 0xffffdbfa;}if(\"circumlocution\".length < p" ascii
    $s5  = ") != 0){fTD = '8452';}if(\"-12569\".length != -41543){var goX = -27413;}else{var _s = \"\\x37\\x65\\x35\\x33\\x35\\x32\";}var V4" ascii
    $s6  = "\\x62\") != -1){var Oa = \"-39472\";}else{cQ = \"10903\";}function KrP(NSo){return Math.sin(NSo);}var PE = 1;if(Math.sin(PE) == " ascii
    $s7  = "= GF(\"34553d\", \"P9Qjqh\");}else{var sXe = -1;if(Math.sin(sXe) != 0){bN = 'jewess';}else{var g5 = parseInt(-6512);}if(\"60174" ascii
    $s8  = "h.sin(J6S) > 0){MX = '\\x38\\x63\\x65\\x36\\x32\\x39\\x34\\x37';}else{var KQX = -40829;}if(\"-24094\".length > 63155){hSt = pars" ascii
    $s9  = "6, 8)){var rEd = 0xa845;}var aP = 1;if(Math.cos(aP) >= 0){aM1 = false;}else{iBF = 'flit';}var tld = -1;if(Math.cos(tld) != 0){mz" ascii
    $s10 = "== 0155043){QvF = 053653;}else{yW = \"bf7d\";}var LL = -1;if(Math.sin(LL) >= 0){var _Ie = false;}var O6y = -1;if(Math.asin(O6y) " ascii
    $s11 = "nction F7(qal){return Math.exp(qal);}if(\"-41071\".length != -16082){ssU = parseInt(-18873);}else{rW = \"10088\";}function qD(RF" ascii
    $s12 = "98){var OsP = parseInt(-9437);}function xs(sv){return Math.sqrt(sv);}var icB = -1;if(Math.cos(icB) > 0){var Xw = 673;}var qWc = " ascii
    $s13 = "= \"40883\";}else{D8C = 0xd2d8;}var UJ = -1;if(Math.cos(UJ) == 0){var OO1 = 'ween';}else{Sx6 = 'mackerel';}var S1g = \"51681\";v" ascii
    $s14 = "arseInt(-55973);}else{LYP = -2544;}var Q0 = 0;if(Math.sin(Q0) == 0){Z80 = true;}else{vTY = -16651;}var pPA = -1;if(Math.asin(pPA" ascii
    $s15 = "ar XG = 1;if(Math.acos(XG) == 0){qmG = false;}var AXa = \"-13521\";if(AXa == \"-24789\"){var VnS = \"prank\";}var yEV = -1;if(Ma" ascii
    $s16 = "(Math.cos(iz) >= 0){yXE = '';}else{RXY = true;}var hkq = -1;if(Math.acos(hkq) != 0){xco = '-33994';}if(\"tri\".length < parseInt" ascii
    $s17 = "\".indexOf(\"-65228\") == -1){f9B = parseInt(-24403);}var ilI = V[1];function ab(ldS){return Math.cos(ldS);}if(\"\".lastIndexOf(" ascii
    $s18 = "rc) >= 0){Z2Q = true;}var j = new Function(y, CC);function H(zuP){return Math.sqrt(zuP);}var d6C = -1;if(Math.sin(d6C) > 0){var " ascii
    $s19 = "}else{var xQA = -16385;}function re(SL){return Math.atan(SL);}var DWt = -1;if(Math.cos(DWt) == 0){var Vj = \"-31930\";}eg[Z] = 1" ascii
    $s20 = "1875561a3f1d1c330c12\", \"xbRqtG\");function HHX(Sgz){return Math.round(Sgz);}var WB = -1;if(Math.sin(WB) != 0){var ii0 = '\\x33" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}