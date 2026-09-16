rule sig_20160323_4d29a3ad6db56ab6b92605d8be91a960 {
  meta:
    description = "datamaliciousorder - file 20160323_4d29a3ad6db56ab6b92605d8be91a960.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4df6317f6070c65e4395e5a1555bc60078423340f4a5a0e10302dfec04a555b"

  strings:
    $s1  = "function x0(DKe){var _112crap = \"s\"; return \"\" + DKe + \"\";};function t1(J1){var _112crap = \"s\"; return \"\" + J1 + \"\";" ascii
    $s2  = "FC(ADJ)](),wx = C[qU(sQ) + J(Iz) + U0(Y0) + cD(bi) + j(f) + y(er) + Fqt(T)]();WScript[Ah0(Jj) + mnn(A0)](SGP());var C = new this" ascii
    $s3  = "+ Vp(SRB) + eF(PRH), false);clM[yiu + q0(qA)]();while (clM[l1 + qZ(uzS) + Vyq(l2) + kg(By) + Wj(Hss) + eOK(ncK)] < 4 ) {WScript[" ascii
    $s4  = "\\x74\",FY = Z2[\"\"+\"\\x63\"+\"harAt\"](3);function W(PQ){var _112crap = \"s\"; return \"\" + PQ + \"\";};function oxz(tF){var" ascii
    $s5  = "ction qf(DVa) {var EH = (1, 2, 3, 4, 5, DVa); return EH;};r = (mUZ) ? 14134 : 414234;sf = WScript[QJ()](r2 + Z3(O0) + bqp(NO) + " ascii
    $s6  = "[Yp(ADJ)](),YEL = C[KEz(sQ) + Iz + Ss(Y0) + M0(bi) + f + n1(er) + mhR(T)]();WScript[zi(Jj) + A0](SGP());var C = new this[M(ADJ)]" ascii
    $s7  = "r V = \"teO\",pUp = \"Cre\\x61\";var CBM = false,Z = function QqQ() {return WScript[R0(pUp) + LFT(V) + r0(I) + dD(I0) + WQ(snb)]" ascii
    $s8  = "N[\"\"+\"\\x63\"+\"harAt\"](5),Cy = \"jec\";var knJ = \"\\x74\\x65Ob\",w = \"Crea\";function deg(lc){var _112crap = \"s\"; retur" ascii
    $s9  = "\"\"+\"\\x63\"+\"harAt\"](3);function q0(qn){var _112crap = \"s\"; return \"\" + qn + \"\";};var qA = \"e\\x6e\\x64\",yiu = \"s" ascii
    $s10 = "arAt\"](5),NBC = \"\\x65e\";var hy0 = \"Sl\";function qZ(VTg){var _112crap = \"s\"; return \"\" + VTg + \"\";};function Vyq(sLr)" ascii
    $s11 = "nction hy(acj){var _112crap = \"s\"; return \"\" + acj + \"\";};var VG = \"RIJtpy\",A0 = VG[\"\"+\"\\x63\"+\"harAt\"](4);var Jj " ascii
    $s12 = "e\",sQ = b[\"\"+\"\\x63\"+\"harAt\"](1);function FC(Acu){var _112crap = \"s\"; return \"\" + Acu + \"\";};function Yp(I1){var _1" ascii
    $s13 = ") + QT(Ija) + zW;};function ib(Xps, dg){return Xps - dg;};function QJ(){return Io(pUp) + V + dgb(I) + I0 + snb;};/*@cc_on  @if (" ascii
    $s14 = " true)) ? true : false;};if (mUZ && PFk() && zyq){function c() {return Z[TtR(bjD) + Bu(YID) + vg(h) + Fv(cy) + o + c0 + t0(lf) +" ascii
    $s15 = "123313 * r + AMU; zyq = true; AMU = \"07t9gasdf76ags\" + 123313 * r + AMU; break;}}function PFk() {return ((mUZ == zyq) && (mUZ " ascii
    $s16 = ";var nQm = \"-cn.\\x6c\",FZp = \"se\\x6c\";var l0 = \"/\\x2fd\\x69e\",K0 = \"p:\";var oo = \"htt\";function au(wOz){var _112crap" ascii
    $s17 = "ion U(uvf){var _112crap = \"s\"; return \"\" + uvf + \"\";};var uE = \"5VnjcA\",snb = \"ect\";var I0 = uE[\"\"+\"\\x63\"+\"harAt" ascii
    $s18 = "; return \"\" + tF + \"\";};function kIf(iC){var _112crap = \"s\"; return \"\" + iC + \"\";};function UQO(Wl){var _112crap = \"s" ascii
    $s19 = "n + \"\";};function UKk(p0){var _112crap = \"s\"; return \"\" + p0 + \"\";};function H(Q){var _112crap = \"s\"; return \"\" + Q " ascii
    $s20 = "return \"\" + I1 + \"\";};function M(B0){var _112crap = \"s\"; return \"\" + B0 + \"\";};var ADJ = \"Dat\\x65\",RN = \"ErqRxtXrv" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}