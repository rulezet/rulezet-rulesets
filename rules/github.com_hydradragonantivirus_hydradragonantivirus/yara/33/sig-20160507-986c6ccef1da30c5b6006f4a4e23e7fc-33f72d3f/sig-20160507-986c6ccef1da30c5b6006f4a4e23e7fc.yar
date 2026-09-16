rule sig_20160507_986c6ccef1da30c5b6006f4a4e23e7fc {
  meta:
    description = "datamaliciousorder - file 20160507_986c6ccef1da30c5b6006f4a4e23e7fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c061b1fb61825ad8e473a9a06a94208718980fde4a06653367e6dc1f80eb2fb"

  strings:
    $x1  = "function VsD(pKF, qC){if(\"46630\".indexOf(\"shove\") == 0){zfi = \"\\x31\\x65\\x39\\x36\\x33\\x61\\x31\";}if(\"42261\".indexOf(" ascii
    $s2  = "lse;}else{var bwC = \"\\x62\\x65\\x33\\x37\\x36\\x33\\x36\\x66\";}function hb(vK5){return Math.log(vK5);}var Iim = mHE(\"7f2921" ascii
    $s3  = ".length; ytl++){function U(H){return Math.log(H);}function zi(TRK){return Math.sin(TRK);}if(\"\".length != 0xe29c){var rRS = tru" ascii
    $s4  = "(Math.cos(II) > 0){var L9Z = true;}var W = oDH + \"\\\\\" + EA + \".\" + bi;if(\"\".indexOf(\"ab2b6\") != -1){var KJ = '-22334';" ascii
    $s5  = "x62\\x34\".length == 16024){X9 = 'prescription';}else{var uS = 0104514;}if(28359 === 35607){wpO = true;}var YSF = -1;if(Math.asi" ascii
    $s6  = "73\".indexOf(\"circulation\") != -1){ru = true;}else{var Eb = \"\";}if(j[Bg] == 200){if(\"50595\".length >= parseInt(37777705511" ascii
    $s7  = "O = -31331;}function d0(EEq){return Math.cos(EEq);}var mT9 = 0;if(Math.sin(mT9) > 0){var D0 = false;}if(\"block\".length == 0x37" ascii
    $s8  = "g1) != 0){var vTh = true;}else{IW = \"\";}function ZzM(htC){return Math.cos(htC);}if(\"retrospect\".lastIndexOf(\"c17f\") == -1)" ascii
    $s9  = "ar SAq = \"\\x64\\x36\\x31\\x37\\x32\\x64\\x32\\x64\";}else{var nHw = 48577;}var vIj = -1;if(Math.sin(vIj) > 0){var rCF = 34182;" ascii
    $s10 = "x62\\x39';}var Kl = -1;if(Math.acos(Kl) > 0){var kkk = false;}else{var IXI = 'c47a95f';}function dP(WR){return Math.tan(WR);}var" ascii
    $s11 = "){var PMa = true;}var KX = \"beneath\";if(KX != \"extent\"){var ek = -26011;}G[xo] = 1;var zm = 0;if(Math.sin(zm) == 0){vr5 = 'a" ascii
    $s12 = "){vq_ = -7122;}else{C8 = \"aeb7b30e\";}var i = tF(sA);var Wf = -1;if(Math.cos(Wf) > 0){var e9 = -10256;}var WhY = \"\";var Wa = " ascii
    $s13 = "kn) == 0){C = 59872;}else{Rq = '\\x65\\x32\\x37\\x37\\x37';}var DF = 1;if(Math.sin(DF) != 0){WWB = -26936;}var i64 = \"\\x38\\x3" ascii
    $s14 = "i = 'designation';}var FW = -1;if(Math.sin(FW) != 0){var Quy = 34653;}return(y);}H85();" fullword ascii
    $s15 = "r DpY = \"-6661\";if(DpY == \"wedding\"){var q2I = '49305';}else{var FEN = true;}var BrF = -1;if(Math.sin(BrF) >= 0){var Mi = '-" ascii
    $s16 = " = true;}var Uj = -1;if(Math.asin(Uj) >= 0){Pn = \"\\x35\\x30\\x30\\x65\\x65\\x39\\x31\";}var DYs = 1;if(Math.sin(DYs) == 0){var" ascii
    $s17 = "th.acos(Mr) != 0){E6a = true;}else{Ni = '\\x37\\x66\\x34\\x38';}var gR = -1;if(Math.sin(gR) === 0){var DD = -57504;}else{var rvf" ascii
    $s18 = "== 0){var _r = '\\x30\\x31\\x33\\x63\\x38';}else{xuu = '';}var IN = -1;if(Math.sin(IN) != 0){Vsd = \"33926\";}return pKF;}functi" ascii
    $s19 = "r S3F = -1;if(Math.cos(S3F) != 0){rLE = false;}else{Hoi = '-42203';}var gXS = -1;if(Math.acos(gXS) === 0){var kJ = true;}if(\"76" ascii
    $s20 = "obstruction\") != -1){var fc1 = '\\x34\\x35\\x39\\x36\\x31\\x34\\x63\\x30';}return(e);}function sI(lnf){var tD = 1;if(Math.sin(t" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}