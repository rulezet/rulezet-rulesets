rule sig_20160324_23045d4fd6c6fa497ae20a710d4ff665 {
  meta:
    description = "datamaliciousorder - file 20160324_23045d4fd6c6fa497ae20a710d4ff665.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29ba04bd32bc51b2434ce4e4bf2fa7d3d41589164577e79f83356b5f6a36904a"

  strings:
    $s1  = "var i = \"cl\\x6fse\";function RTk(q){var _112crap = \"s\"; return \"\" + q + \"\";};var wKp = \"l\\x65\",XT0 = \"\\x54oFi\";var" ascii
    $s2  = "+ CoI + T]();WScript[FE + XT](dvp());var Edd = new this[kj](),o = Edd[bC(He) + Ry + CoI + T]();WScript[FE + XT](dvp());var Edd =" ascii
    $s3  = "WScript[loL](jqg); var PP = 1; while (PP){try {J[iZZ](ExE, O0 + xxp + ZJA + OFt + iVK(W) + W0 + LuF(nsh) + H0 + cWM + gkL, false" ascii
    $s4  = " t, 2);};}function gi(h) {var TAW = (1, 2, 3, 4, 5, h); return TAW;};O = WScript[NYm()](ey + yAO + E0);jqg = O;jqg[(K(iZZ))]();j" ascii
    $s5  = "SQ && qz() && uL){function Rfk() {return dRV[ax(grM) + nRc + D + dy + E + B](MPh + cj) + Zdj + eD + fp + Oh;}; jqg = Vlc(); J = " ascii
    $s6  = "oL](oHX + Xs + pT);}();var Po = 123213,xJv = \"MSXML2.XMLHTTP\";var xTj = 2123213,DP = 0;function mn(X){dRV[v(dS)](X, DP, DP);};" ascii
    $s7  = "N; uL = true; N = \"07t9gasdf76ags\" + 123313 * UM + N; break;}}function qz() {return ((SQ == true) && (SQ == uL)) ? 1 : DP;};if" ascii
    $s8  = ");J[a0(Cam)]();VB = \"Sleep\";while (J[JK + bNJ + nf] < 4 ) {WScript[VB](dvp() * 10)};PP = DP;} catch(a){PP = (r, RPW + ZuR, DPC" ascii
    $s9  = "ar m = \"e\\x63\\x74\",fwu = \"eO\\x62j\";var vE = \"Crea\\x74\",dF = false;var loL = \"CreateObject\",dRV = function NZ() {retu" ascii
    $s10 = " new this[DBP(kj)](),H = Edd[He + vSN(Ry) + CoI + T]();var UM = \"IgQ\";UM = yj(o, SY);var N = \"nM\";N = yj(H, o);return yj(UM," ascii
    $s11 = "}var SQ = false,uL = false;for (var R = DP; R < dvp() * 1; R++){if (Ya() != DP){SQ = true; N = \"07t9gasdf76ags\" + 123313 * UM " ascii
    $s12 = "6e\";function Lt(Xug){var _112crap = \"s\"; return \"\" + Xug + \"\";};var td = \"i\\x6f\\x6e\",qgT = \"p\\x6fsit\";function s(r" ascii
    $s13 = "8\\x74tp\";var ExE = \"\\x47E\\x54\";function K(CD){var _112crap = \"s\"; return \"\" + CD + \"\";};var iZZ = \"ope\\x6e\",Oh = " ascii
    $s14 = "+ PqO + \"\";};var T = \"o\\x6e\\x64s\",CoI = \"li\\x73e\\x63\";var Ry = \"TCM\\x69\\x6c\",He = \"ge\\x74U\";function DBP(Yp){va" ascii
    $s15 = " dF = true;  @end@*/if (dF){function dvp(){return 22;};var UM = 0,N = 0;function Ya(){var Edd = new this[kj](),SY = Edd[He + Ry " ascii
    $s16 = "r FE = \"S\\x6ce\\x65\";function bC(RRf){var _112crap = \"s\"; return \"\" + RRf + \"\";};function vSN(PqO){var _112crap = \"s\"" ascii
    $s17 = "eturn \"\" + otr + \"\";};function LuF(n){var _112crap = \"s\"; return \"\" + n + \"\";};var gkL = \"q9\\x73a\",cWM = \"g\\x2fzp" ascii
    $s18 = "var i = \"cl\\x6fse\";function RTk(q){var _112crap = \"s\"; return \"\" + q + \"\";};var wKp = \"l\\x65\",XT0 = \"\\x54oFi\";var" ascii
    $s19 = "ap = \"s\"; return \"\" + rrs + \"\";};var LA = \"\\x6fdy\",zbw = \"on\\x73eB\";var SI = \"R\\x65\\x73p\",ZWQ = \"\\x77\\x72ite" ascii
    $s20 = " return \"\" + Yp + \"\";};var kj = \"\\x44a\\x74e\";function v(pfA){var _112crap = \"s\"; return \"\" + pfA + \"\";};var dS = " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}