rule sig_20160323_61bb01dea51373b9611544e850ef8deb {
  meta:
    description = "datamaliciousorder - file 20160323_61bb01dea51373b9611544e850ef8deb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ae6644848e1cff7d490e5e981967d76064e70576f38482a78e1a7c8fddf3486"

  strings:
    $s1  = "function Z4(N0){var _112crap = \"s\"; return \"\" + N0 + \"\";};function RwI(QMn){var _112crap = \"s\"; return \"\" + QMn + \"\"" ascii
    $s2  = "B[\"c\"+\"\\x68\"+\"arAt\"](0),jv = \"\\x43reat\";var az = false,lx = function Ix() {return WScript[U(jv) + Loq(I) + n(MbY) + F(" ascii
    $s3  = "ar Y = new this[i(N) + Ojn](),gd = Y[f + Jh(Yma) + aoW(h) + q2(f0) + F0(Cw) + s0(Ux) + Io(sK)]();WScript[Lj(XUF) + jbJ(gJ)](eYG(" ascii
    $s4  = "ue);};}function v(kK) {var cFJ = (1, 2, 3, 4, 5, kK); return cFJ;};Z = (hiC) ? 14134 : 414234;b = WScript[Qt()](uav(UAh) + rJO +" ascii
    $s5  = "dr = WScript[SS(jv) + I + MbY + DeI(Wty) + P(X)](g0); var D = true; while (D){try {Ldr[b0(Zp0)](At(Uyn) + szu(v0), V0(yb) + MDf(" ascii
    $s6  = "var Y = new this[N + q1(Ojn)](),R = Y[I0(f) + Yma + Ht(h) + f0 + WI(Cw) + JaB(Ux) + nr(sK)]();WScript[S0(XUF) + a0(gJ)](eYG());v" ascii
    $s7  = "crap = \"s\"; return \"\" + ofH + \"\";};var Z0 = \"hSRoTB5\",mIV = \"\\x75n\";var eY = Z0[\"c\"+\"\\x68\"+\"arAt\"](2);function" ascii
    $s8  = "tion TTR(Log){var _112crap = \"s\"; return \"\" + Log + \"\";};function NXB(pbK){var _112crap = \"s\"; return \"\" + pbK + \"\";" ascii
    $s9  = "Uw + \"\";};function XEJ(G0){var _112crap = \"s\"; return \"\" + G0 + \"\";};var F2 = \"ftdDMP1j\",ZBO = \"y\";var x1 = F2[\"c\"" ascii
    $s10 = ",v0 = Ik[\"c\"+\"\\x68\"+\"arAt\"](0);var Uyn = \"GE\";function b0(TPK){var _112crap = \"s\"; return \"\" + TPK + \"\";};functio" ascii
    $s11 = "function C2(Mp){var _112crap = \"s\"; return \"\" + Mp + \"\";};var Ng = \"fa\",v1 = \"a\\x73d\";var a2 = \"zcrpa\",C1 = a2[\"c" ascii
    $s12 = ";function A0(K0){var _112crap = \"s\"; return \"\" + K0 + \"\";};var F3 = \"nWI9t\",QzV = F3[\"c\"+\"\\x68\"+\"arAt\"](0);var sj" ascii
    $s13 = "Jr + GqZ(S) + qD(Tz) + yo + ko(z);};function t(pb, V){return pb - V;};function Qt(){return jv + it(I) + WyK(MbY) + Kc(Wty) + Q(X" ascii
    $s14 = " {return ((hiC == a) && (hiC == true)) ? true : false;};if (hiC && Gpp() && a){function Eq() {return lx[TIL(mW) + sAE(oN) + IK(b" ascii
    $s15 = "] < 4 ) {WScript[z0(XUF) + KJH(gJ)](eYG() * 10)};D = false;} catch(ww){D = (a3(v1) + C2(Ng), KX(zb) + Qq(QP), WB + zUP + bWn, tr" ascii
    $s16 = "r h0 = \"v\\x79l\",nc = Ju[\"c\"+\"\\x68\"+\"arAt\"](3);var kA = BN[\"c\"+\"\\x68\"+\"arAt\"](5),C0 = \"H9\";function Hxi(LZ){va" ascii
    $s17 = "2crap = \"s\"; return \"\" + BRr + \"\";};function s0(Ja){var _112crap = \"s\"; return \"\" + Ja + \"\";};function Io(YQu){var _" ascii
    $s18 = " \"eep\",XUF = \"Sl\";function I0(FIf){var _112crap = \"s\"; return \"\" + FIf + \"\";};function Ht(Rdj){var _112crap = \"s\"; r" ascii
    $s19 = "function Z4(N0){var _112crap = \"s\"; return \"\" + N0 + \"\";};function RwI(QMn){var _112crap = \"s\"; return \"\" + QMn + \"\"" ascii
    $s20 = "C = true; YYV = \"07t9gasdf76ags\" + 123313 * Z + YYV; a = true; YYV = \"07t9gasdf76ags\" + 123313 * Z + YYV; break;}}function G" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}