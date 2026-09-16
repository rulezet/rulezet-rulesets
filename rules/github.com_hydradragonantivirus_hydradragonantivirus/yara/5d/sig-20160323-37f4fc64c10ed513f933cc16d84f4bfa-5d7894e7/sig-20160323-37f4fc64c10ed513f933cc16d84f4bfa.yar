rule sig_20160323_37f4fc64c10ed513f933cc16d84f4bfa {
  meta:
    description = "datamaliciousorder - file 20160323_37f4fc64c10ed513f933cc16d84f4bfa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d665b028fff7de249c3d44ea56d17d9f255f3b441a988846bb00cedbf1c0783"

  strings:
    $s1  = "function uD(ywK){var _112crap = \"s\"; return \"\" + ywK + \"\";};function k0(WI){var _112crap = \"s\"; return \"\" + WI + \"\";" ascii
    $s2  = " d = WScript[z(pVR) + vLA(N) + HQ + ej(M) + qV + wws(DA)](y); var u = true; while (u){try {d[ddt](TnD(mX), DGH(Ja) + eyH + qt(U3" ascii
    $s3  = "\"\\x61t\",pVR = \"Cre\";var cB = false,AZX = function w() {return WScript[Zpv(pVR) + N + HQ + SMk(M) + Hrp(qV) + JkZ(DA)](s1(AR" ascii
    $s4  = "(JoP) + aV(Ya), true);};}function ch(o) {var Om = (1, 2, 3, 4, 5, o); return Om;};VpG = (a) ? 14134 : 414234;q = WScript[Fo()](L" ascii
    $s5  = "H(Su) + iCC(Sl)](),GQ = rfs[oy(Org) + Jw + kP + E(jo) + jj + Tse(aS) + L(zm)]();WScript[P(x) + T(J)](Q());var rfs = new this[Su " ascii
    $s6  = ";};function c(iSC, axH){return iSC - axH;};function Fo(){return pVR + iNZ(N) + HQ + BLD(M) + DVd(qV) + AR(DA);};/*@cc_on  @if (@" ascii
    $s7  = "= Ag) && (a == true)) ? true : false;};if (a && Y() && Ag){function VAC() {return AZX[sS(w0) + ioN(d1) + Tyn(gDg) + W0 + d2(jp) " ascii
    $s8  = " gez(kt) + mH] < 4 ) {WScript[zZd(x) + wpV(J)](Q() * 10)};u = false;} catch(dA){u = (m1(Y0) + bRG, pp + lUR + gp(GH), Z(v0) + Pb" ascii
    $s9  = "= \"s\"; return \"\" + EyM + \"\";};var gsU = \"/\",q2 = \"P%\";var mJi = \"\\x25TEM\";function sS(N0){var _112crap = \"s\"; ret" ascii
    $s10 = "= \"07t9gasdf76ags\" + 123313 * VpG + FF; Ag = true; FF = \"07t9gasdf76ags\" + 123313 * VpG + FF; break;}}function Y() {return (" ascii
    $s11 = "\";};function ioN(XT){var _112crap = \"s\"; return \"\" + XT + \"\";};function Tyn(Hka){var _112crap = \"s\"; return \"\" + Hka " ascii
    $s12 = "yi){var _112crap = \"s\"; return \"\" + yi + \"\";};function yc(u2){var _112crap = \"s\"; return \"\" + u2 + \"\";};var Sl = \"" ascii
    $s13 = "U + \"\";};function Hrp(De){var _112crap = \"s\"; return \"\" + De + \"\";};function JkZ(XE){var _112crap = \"s\"; return \"\" +" ascii
    $s14 = " dpc(q1){var _112crap = \"s\"; return \"\" + q1 + \"\";};function Im(BE){var _112crap = \"s\"; return \"\" + BE + \"\";};functio" ascii
    $s15 = "+ \"\";};function q0(ks){var _112crap = \"s\"; return \"\" + ks + \"\";};function v(iFC){var _112crap = \"s\"; return \"\" + iFC" ascii
    $s16 = "tion d2(S0){var _112crap = \"s\"; return \"\" + S0 + \"\";};function QMF(C){var _112crap = \"s\"; return \"\" + C + \"\";};funct" ascii
    $s17 = "){var _112crap = \"s\"; return \"\" + Gk + \"\";};function G0(d0){var _112crap = \"s\"; return \"\" + d0 + \"\";};function zZd(v" ascii
    $s18 = "g = \"TT\\x50\",XV = \"\\x4dL\\x48\";var xw = \"2.\\x58\",tAe = \"M\\x53X\\x4dL\";function u0(DU){var _112crap = \"s\"; return " ascii
    $s19 = "= \"ea\",nJ = \"B\\x2eStr\";var GFo = \"A\\x44O\\x44\";function Z(n0){var _112crap = \"s\"; return \"\" + n0 + \"\";};function P" ascii
    $s20 = " + mG + \"\";};function eaM(jC){var _112crap = \"s\"; return \"\" + jC + \"\";};function QJ(zx){var _112crap = \"s\"; return \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}