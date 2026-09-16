rule sig_20160505_d3ba5c0988cb0c3a19479da37fe29b62 {
  meta:
    description = "datamaliciousorder - file 20160505_d3ba5c0988cb0c3a19479da37fe29b62.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40f1cbe734c67d3ebc07904f23eca7b1fa744c93cc834cc71580efdfcd3edfe8"

  strings:
    $x1  = "function B(H, aEh){if(\"53954\".length <= parseInt(11111001111010, 2)){var Z = parseInt(-17418);}if(046002 < 57788){var NH = \"" ascii
    $s2  = "\\x33\\x38\\x31\\x64\\x32\\x61\";}var C = 1;if(Math.asin(C) >= 0){aC = \"\";}function x(VF){return Math.log(VF);}if(\"-29635\".i" ascii
    $s3  = "43e0f6';}else{tU4 = 'vagrant';}OhR = OhR + 1;var v = -1;if(Math.asin(v) > 0){var ki = 0x5cb;}if(parseInt(11111111111111111100110" ascii
    $s4  = " -1;if(Math.sin(xa4) != 0){gE = '-23066';}else{var ZyF = parseInt(11111111111111111110110000001101, 2);}return(NkJ);}function Wj" ascii
    $s5  = "00100110, 2);}var Cm = -1;if(Math.cos(Cm) === 0){var v6 = parseInt(11111111111111110011110010111111, 2);}else{oCG = \"\";}var jV" ascii
    $s6  = " != 0){var ze = parseInt(11111111111111110010011000110000, 2);}else{h7 = parseInt(-19053);}var EV = -1;if(Math.sin(EV) === 0){va" ascii
    $s7  = " iZG = -1;if(Math.sin(iZG) >= 0){sDC = false;}var XHT = \"-30614\";if(XHT != \"explains\"){var yus = parseInt(1000011100001100, " ascii
    $s8  = "f(\"\".lastIndexOf(\"\\x34\\x61\\x33\\x33\\x65\") != -1){EzT = '-10696';}var Bg = 0;if(Math.cos(Bg) > 0){puc = true;}if(\"-1636" ascii
    $s9  = " \"c851a9\";if(jV === \"27190\"){var vsn = true;}return(Zn);}function i(w){var bsz = -1;if(Math.cos(bsz) != 0){s = '\\x33\\x66" ascii
    $s10 = "(WT) > 0){Qc = true;}return(FT);}function l(){var tgA = -1;if(Math.sin(tgA) >= 0){var FA9 = \"14317\";}var QJ = 0;if(Math.asin(Q" ascii
    $s11 = "= -34179;}var hdM = -1;if(Math.cos(hdM) == 0){UAC = true;}if(\"\" == \"puzzles\"){hi = 0xffff344f;}if(QI[SW] == 200){var rkt = 0" ascii
    $s12 = "V = 0;if(Math.cos(oV) === 0){DM8 = \"d7953775\";}else{fJy = -9261;}function FAh(MV){return Math.abs(MV);}r[q]();if(0xe29 > 06073" ascii
    $s13 = "\") == -1){GKP = 0x67da;}var ayp = EA(\"1800170f\", \"key\");var yyR = \"-17996\";var Ox = \"\";if(yyR == Ox){var l2w = \"\";}el" ascii
    $s14 = "f(Math.cos(nf) == 0){OLB = false;}var DoM = -1;if(Math.cos(DoM) > 0){ucZ = parseInt(106420, 8);}var UEi = -1;if(Math.asin(UEi) >" ascii
    $s15 = "1){Jon = 0xffff471b;}else{h_c = \"\\x63\\x34\\x64\\x63\";}var nxG = -1;if(Math.cos(nxG) === 0){YyM = true;}if(\"46647\".indexOf(" ascii
    $s16 = " 0){mtG = \"entrance\";}var X7 = B(p, aEh);if(\"\" != \"unbiased\"){PD1 = false;}else{kt = '740f0a';}var l6 = -1;if(Math.cos(l6)" ascii
    $s17 = "r Am = '9cc982';}var JL = -1;if(Math.asin(JL) != 0){var HV = 'factotum';}else{ekp = '-41002';}function vf(_K){return Math.tan(_K" ascii
    $s18 = " OF = \"-34597\";}Q[ELG](I + \" \" + qM + \" \" + P, 1, 0);break;case 1:var Iv = \"temporarily\";if(Iv != \"\\x39\\x65\\x64\\x30" ascii
    $s19 = " >= 0){var vez = -13694;}else{var Sj = \"32198\";}if(\"19631\" == \"54840\"){nTm = false;}var oSd = 1;if(Math.cos(oSd) == 0){t8Y" ascii
    $s20 = "3\\x32\\x63\";}var psV = -1;if(Math.cos(psV) >= 0){var It = parseInt(-51972);}else{MI = 0xffff7677;}var OhR = 0;if(parseInt(-214" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}