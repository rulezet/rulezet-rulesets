rule sig_20160323_b08e133d0c2f320fb6ba296d1f211ad6 {
  meta:
    description = "datamaliciousorder - file 20160323_b08e133d0c2f320fb6ba296d1f211ad6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1547aa5e85cbd226a9b025c1287eaa599f78d4c4a8a4c77140f13996dd9f94d5"

  strings:
    $s1  = "function wC(v1){var _112crap = \"s\"; return \"\" + v1 + \"\";};var kB = \"los\\x65\",jO0 = \"c\";function f1(v0){var _112crap =" ascii
    $s2  = " = function B() {return WScript[FQ(zx) + crc + dri(F) + tg(S) + EtX](lsE(X) + QNz(IRs) + ciO + yWW(p0));}();function Z(t){jdQ[uM" ascii
    $s3  = "(e0){var _112crap = \"s\"; return \"\" + e0 + \"\";};var ef = \"ymvs\",sW = \"enpgrt\";var jjJ = \"e\",nvK = sW[\"\"+\"\\x63\"+" ascii
    $s4  = "turn \"\" + SDa + \"\";};var xVM = \"qbp8l\",Z5 = \"\\x65\";var y0 = xVM[\"\"+\"\\x63\"+\"harAt\"](2),xI = \"t\\x79\";var rZ = " ascii
    $s5  = "](t, 0, 0);};function CQ(){return Z2(LH) + K(k) + L(n) + l + g(rYD) + an(Xo);};function SE(gd, P){return gd - P;};function uu(){" ascii
    $s6  = "urn ((ba == ksB) && (ba == true)) ? true : false;};if (ba && Uo() && ksB){function f() {return jdQ[J0(voB) + qb(WZ) + R + qTW(iE" ascii
    $s7  = "4d\",uM = \"Run\";function lsE(NIh){var _112crap = \"s\"; return \"\" + NIh + \"\";};function QNz(XDq){var _112crap = \"s\"; ret" ascii
    $s8  = " + tr(ln)](BTf());var sn = new this[n0(Vhi)](),LA = sn[GOa(Mk) + cAU + S1 + Zt(B1) + AeY(GI0)]();WScript[tv(x0) + eZt(ln)](BTf()" ascii
    $s9  = "22;};var Z0 = 0,LzV = 0;function yM(){var sn = new this[ZYX(Vhi)](),w = sn[Ck(Mk) + c(cAU) + S1 + RI(B1) + E0(GI0)]();WScript[x0" ascii
    $s10 = "g3 + Qdt(nvK) + w2(jjJ)] < 4 ) {WScript[yXl(x0) + ln](BTf() * 10)};GI = false;} catch(TEU){GI = (Lew(ju) + wEd(WMa) + Mcj, uH(qZ" ascii
    $s11 = "c\\x74\",S = \"b\\x6a\\x65\";var F = kHH[\"\"+\"\\x63\"+\"harAt\"](4),crc = ZNJ[\"\"+\"\\x63\"+\"harAt\"](0);var zx = \"Cre\\x61" ascii
    $s12 = " = \"a\",t1 = \"st\";var z = ef[\"\"+\"\\x63\"+\"harAt\"](0),g2 = \"ad\";var Q1 = \"\\x72\\x65\",g1 = \"\\x73end\";function pS(f" ascii
    $s13 = ";};function eZt(O){var _112crap = \"s\"; return \"\" + O + \"\";};function yXl(dR){var _112crap = \"s\"; return \"\" + dR + \"\"" ascii
    $s14 = "3c\\x72i\";function FQ(trg){var _112crap = \"s\"; return \"\" + trg + \"\";};function dri(Ygk){var _112crap = \"s\"; return \"\"" ascii
    $s15 = "g) + Y + j0(I1), mc(pj) + m2(cjo), true);};}function CrP(GT) {var tAU = (1, 2, 3, 4, 5, GT); return tAU;};Z0 = (ba) ? 14134 : 41" ascii
    $s16 = "; LzV = \"07t9gasdf76ags\" + 123313 * Z0 + LzV; ksB = true; LzV = \"07t9gasdf76ags\" + 123313 * Z0 + LzV; break;}}function Uo() " ascii
    $s17 = "n \"\" + v0 + \"\";};var X0 = \"\\x46il\\x65\",xv = \"eTo\";var nZD = \"Sav\",eX = \"tion\";var aod = \"posi\";function gNs(zT){" ascii
    $s18 = "crap = \"s\"; return \"\" + eNQ + \"\";};function K(y){var _112crap = \"s\"; return \"\" + y + \"\";};function L(Q){var _112crap" ascii
    $s19 = "function wC(v1){var _112crap = \"s\"; return \"\" + v1 + \"\";};var kB = \"los\\x65\",jO0 = \"c\";function f1(v0){var _112crap =" ascii
    $s20 = "V = SE(Mr, LA);return SE(Z0, LzV);}var ba = false,ksB = false;for (var kSX = 0; kSX < BTf() * 1; kSX++){if (yM() != 0){ba = true" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}