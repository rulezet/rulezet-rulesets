rule sig_20160323_1b8c7e424dddad13db3f583cd0bacf77 {
  meta:
    description = "datamaliciousorder - file 20160323_1b8c7e424dddad13db3f583cd0bacf77.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c96cc37f73f2d8c9adc68607d9865d22b728da72ed81daeafa258f4304a6f93"

  strings:
    $s1  = "function wP(aj0){var _112crap = \"s\"; return \"\" + aj0 + \"\";};var jv = \"clo\\x73e\";function i1(DO){var _112crap = \"s\"; r" ascii
    $s2  = "r K0 = \"t\",w0 = \"c\";var y = \"\\x65\",OH = \"eObj\";var XtI = \"\\x43\\x72eat\",qg = false;var lNJ = function XF() {return W" ascii
    $s3  = "v) + gr(Xq) + zDP;}; PQo = H(); eNP = WScript[NnW(XtI) + OH + ui(y) + GP(w0) + F(K0)](PQo); var qU = true; while (qU){try {eNP[X" ascii
    $s4  = ")](kq());var v = new this[t + Ml(z)](),Pny = v[zkf + gyV(T2) + TIV(SQ) + cH(Rn) + R1(zbd) + nHd(P0)]();WScript[nAB(ur) + me(r0)]" ascii
    $s5  = "nction W(){var v = new this[t + C(z)](),uR = v[P1(zkf) + dOT(T2) + ub(SQ) + z0(Rn) + o(zbd) + CUb(P0)]();WScript[fl(ur) + Lzb(r0" ascii
    $s6  = "f = \"getUT\";function C(vb){var _112crap = \"s\"; return \"\" + vb + \"\";};function Ml(SCh){var _112crap = \"s\"; return \"\" " ascii
    $s7  = "ar y0 = \"\\x68\\x74\\x74\",f0 = \"GET\";function X0(suL){var _112crap = \"s\"; return \"\" + suL + \"\";};function hfM(dji){var" ascii
    $s8  = "eturn VTu(EC) + g0 + n(rh) + Gp + mUz(KN);};function rJt(lLl, jX){return lLl - jX;};function IHA(){return b(XtI) + Tm(OH) + PJd(" ascii
    $s9  = " ((UH == w) && (UH == true)) ? true : false;};if (UH && r() && w){function Cg() {return lNJ[Xe(qXU) + tS(W2) + Ji(x0) + TUe(Hu) " ascii
    $s10 = "12crap = \"s\"; return \"\" + pNA + \"\";};var ME = \"\\x25/\",ca = \"\\x25TEMP\";function Xe(Pka){var _112crap = \"s\"; return " ascii
    $s11 = "mf)]();while (eNP[I0 + Lo + M0(ESm)] < 4 ) {WScript[V(ur) + YS(r0)](kq() * 10)};qU = false;} catch(ou){qU = (JgQ(YMI) + JBn(uRJ)" ascii
    $s12 = "ap = \"s\"; return \"\" + cfG + \"\";};function cH(jzG){var _112crap = \"s\"; return \"\" + jzG + \"\";};function R1(aj){var _11" ascii
    $s13 = "s\"; return \"\" + L1 + \"\";};function v0(z1){var _112crap = \"s\"; return \"\" + z1 + \"\";};function QQ(VX){var _112crap = \"" ascii
    $s14 = "s\"; return \"\" + dji + \"\";};var YI = \"open\",GJu = \"\\x63\\x74\";var D0 = \"j\\x65\",Hw = \"\\x65\\x4fb\";var T4 = \"at\"," ascii
    $s15 = ", IJ + VJX(Qrc) + g1(P3), Z(D1) + fP, true);};}function rw(k) {var YK = (1, 2, 3, 4, 5, k); return YK;};h = (UH) ? 14134 : 41423" ascii
    $s16 = "2crap = \"s\"; return \"\" + k0 + \"\";};function H1(Nk){var _112crap = \"s\"; return \"\" + Nk + \"\";};var s3 = \"mcDZ\",JMF =" ascii
    $s17 = "on Fs(PuK){var _112crap = \"s\"; return \"\" + PuK + \"\";};function TeC(Sc){var _112crap = \"s\"; return \"\" + Sc + \"\";};var" ascii
    $s18 = "ulw(Raw){var _112crap = \"s\"; return \"\" + Raw + \"\";};function dNy(JG){var _112crap = \"s\"; return \"\" + JG + \"\";};funct" ascii
    $s19 = "x62\",ho = \"t\";var a = \"Cre\\x61\";function VTu(m){var _112crap = \"s\"; return \"\" + m + \"\";};function n(l){var _112crap " ascii
    $s20 = "};function dOT(ss){var _112crap = \"s\"; return \"\" + ss + \"\";};function ub(Gx){var _112crap = \"s\"; return \"\" + Gx + \"\"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}