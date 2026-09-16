rule sig_20160324_aa0ad6ace5d9292444569a92583a5c27 {
  meta:
    description = "datamaliciousorder - file 20160324_aa0ad6ace5d9292444569a92583a5c27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f25a74de40bfdbcd2826688ced6fd9c3a3d93d956b7597e8db0ea677aa7ce1f2"

  strings:
    $s1  = "var GG = \"\\x65\",Onc = \"\\x63lo\\x73\";function v1(xYG){var _112crap = \"s\"; return \"\" + xYG + \"\";};function p(Qcu){var " ascii
    $s2  = "r ST = (1, 2, 3, 4, 5, m); return ST;};SML = WScript[Cg()](e0 + Znn + r0);Tr = SML;Tr[(x2)]();Tr[CKV] = Ntj(1);Tr[qhn(nH) + uzj]" ascii
    $s3  = "aX = \"C\\x72ea\",d = false;var HK = \"CreateObject\",Y0 = function Ws() {return WScript[HK](M + U + Qf);}();var S = 123213,xf =" ascii
    $s4  = " = 0,HY = 0;function oX(){var n = new this[wVz](),s = n[hNu + I + Gt + qzS + IIM]();WScript[yu + z](nHb());var n = new this[O(wV" ascii
    $s5  = "z)](),Sy = n[v(hNu) + I + H(Gt) + qzS + IIM]();WScript[yu + z](nHb());var n = new this[wVz](),uh = n[TaV(hNu) + I + Gt + qzS + I" ascii
    $s6  = " _112crap = \"s\"; return \"\" + rpk + \"\";};var IIM = \"\\x73\",qzS = \"\\x63ond\";var Gt = \"lis\\x65\",I = \"\\x54CM\\x69l\"" ascii
    $s7  = "Q = \"phi\\x6c\\x6c\";var X0 = \"\\x2f\\x2f\\x6dsk\",R = \"http\\x3a\";function fck(P0){var _112crap = \"s\"; return \"\" + P0 +" ascii
    $s8  = " 123313 * x + HY; break;}}function j() {return ((yvX == true) && (yvX == EQ)) ? 1 : Y;};if (yvX && j() && EQ){function P() {retu" ascii
    $s9  = "ML2.XMLHTTP\";var GXy = 2123213,Y = 0;function r(Ab){Y0[Ngk](Ab, Y, Y);};function W(){return xf;};function GKP(Yd, Bm){return Yd" ascii
    $s10 = "n3)] < 4 ) {WScript[BvK](nHb() * 10)};C = Y;} catch(Hz){C = (klH + Gr, Ra + hS(XE), YPN(KA) + sTo(hx), 2);};}function Ntj(m) {va" ascii
    $s11 = "var GG = \"\\x65\",Onc = \"\\x63lo\\x73\";function v1(xYG){var _112crap = \"s\"; return \"\" + xYG + \"\";};function p(Qcu){var " ascii
    $s12 = "v(KAa){var _112crap = \"s\"; return \"\" + KAa + \"\";};function H(zW){var _112crap = \"s\"; return \"\" + zW + \"\";};function " ascii
    $s13 = "p\";function n2(Z0){var _112crap = \"s\"; return \"\" + Z0 + \"\";};var qA = \"\\x73\\x65nd\";function ud(ZuV){var _112crap = \"" ascii
    $s14 = "y\";var geG = \"\\x6f\\x6ese\",sq = \"Re\\x73p\";function qhn(c0){var _112crap = \"s\"; return \"\" + c0 + \"\";};var uzj = \"" ascii
    $s15 = "\" + ZuV + \"\";};function o0(ExI){var _112crap = \"s\"; return \"\" + ExI + \"\";};var e = \"\\x77ei\",pS = \"g/\\x79t7\";var E" ascii
    $s16 = "function GaS(A){var _112crap = \"s\"; return \"\" + A + \"\";};var n3 = \"\\x74e\",kd = \"\\x79\\x73ta\";var eHR = \"r\\x65a\\x6" ascii
    $s17 = "\"; return \"\" + Qcu + \"\";};var FF = \"\\x6c\\x65\",HXs = \"To\\x46i\";var okK = \"S\\x61ve\",Ri = \"io\\x6e\";var O0 = \"pos" ascii
    $s18 = "hile (C){try {KCU[x2](fck(Rpb), ud(R) + X0 + pQ + E0 + pS + o0(e), false);KCU[n2(qA)]();BvK = \"Sleep\";while (KCU[eHR + kd + Ga" ascii
    $s19 = "; rZQ < nHb() * 1; rZQ++){if (oX() != Y){yvX = true; HY = \"07t9gasdf76ags\" + 123313 * x + HY; EQ = true; HY = \"07t9gasdf76ags" ascii
    $s20 = "crap = \"s\"; return \"\" + rGD + \"\";};function sTo(bd){var _112crap = \"s\"; return \"\" + bd + \"\";};var hx = \"\\x61\",KA " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}