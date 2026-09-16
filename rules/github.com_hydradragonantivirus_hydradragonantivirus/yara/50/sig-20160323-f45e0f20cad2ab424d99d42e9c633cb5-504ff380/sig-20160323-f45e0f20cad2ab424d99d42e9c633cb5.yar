rule sig_20160323_f45e0f20cad2ab424d99d42e9c633cb5 {
  meta:
    description = "datamaliciousorder - file 20160323_f45e0f20cad2ab424d99d42e9c633cb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4068d75542a27bff443b9383b6e9cec88d8bc586fffb22fb4fcf09c110de91e7"

  strings:
    $s1  = "function lQh(R1){var _112crap = \"s\"; return \"\" + R1 + \"\";};function GV(QOd){var _112crap = \"s\"; return \"\" + QOd + \"\"" ascii
    $s2  = "bqZ(); Qtw = WScript[Jq + YN + PPX(Aw) + BPt(K) + p(IU)](l); var Y = true; while (Y){try {Qtw[vW(iv) + QaY + kC(eDq)](FP, E(zg) " ascii
    $s3  = "YA), true);};}function Ud(jf) {var fF = (1, 2, 3, 4, 5, jf); return fF;};ln = (Lv) ? 14134 : 414234;Ptz = WScript[U()](Bc(O3) + " ascii
    $s4  = "1(SC)](),Im = u[XHa(eGm) + Q0(uox) + Iwl(Ymy) + NFj(cB) + X + G0 + I0(Awl)]();WScript[SeU(i2) + pE(G1)](ll());var u = new this[Y" ascii
    $s5  = "IC(U0) + P(SC)](),AFr = u[Z(eGm) + Rt(uox) + Ymy + ja(cB) + X + G0 + Dmx(Awl)]();WScript[tw(i2) + G1](ll());var u = new this[bZk" ascii
    $s6  = "x65\";var Hnc = false,PvS = function Xk() {return WScript[pSm(Jq) + arr(YN) + Aw + i0(K) + H(IU)](Afz(fk) + Yq(G) + oXR(HTq) + y" ascii
    $s7  = "+ S0 + K2(i4) + Yhv(QZJ) + a2(pH0) + xQs(qYd) + s(B1), false);Qtw[w(S2)]();while (Qtw[TXl(AZn) + s0 + hf(AhV)] < 4 ) {WScript[Am" ascii
    $s8  = "var _112crap = \"s\"; return \"\" + t2 + \"\";};var n = \"S\",G1 = \"leep\";var i2 = n[\"\"+\"\\x63\"+\"harAt\"](0);function XHa" ascii
    $s9  = ",wS = Xl[\"\"+\"\\x63\"+\"harAt\"](5);var FMB = \"\\x61\",O2 = \"f\";function YE(xG){var _112crap = \"s\"; return \"\" + xG + \"" ascii
    $s10 = "KS){var _112crap = \"s\"; return \"\" + KS + \"\";};var MCn = \"\\x70e\",R0 = \"t\\x79\";var sgj = \"VnFM2va\",rxo = sgj[\"\"+\"" ascii
    $s11 = "};function t0(Tp){var _112crap = \"s\"; return \"\" + Tp + \"\";};var UpJ = \"Q2Xe0z\",TlT = \"vP\";var ia = TlT[\"\"+\"\\x63\"+" ascii
    $s12 = " \"HVilSchSsuL\",mFb = \"\\x6cos\\x65\";var fb = MUI[\"\"+\"\\x63\"+\"harAt\"](5);function F0(Z1){var _112crap = \"s\"; return " ascii
    $s13 = "s\"; return \"\" + i5 + \"\";};var snk = \"soi4yC\",P3 = \"n\";var Jo = snk[\"\"+\"\\x63\"+\"harAt\"](1),eU = \"\\x74i\";var G2 " ascii
    $s14 = " = \"TT\";var k0 = \"H\",YG = \"M\\x4c\";var t = UpJ[\"\"+\"\\x63\"+\"harAt\"](2),gP = \"2.\";var Qx = \"MSXML\",eCm = \"Run\";f" ascii
    $s15 = "function i(EM, Ejr){return EM - Ejr;};function U(){return EgI(Jq) + NMX(YN) + i1(Aw) + k(K) + hDq(IU);};/*@cc_on  @if (@_win32 |" ascii
    $s16 = " == VG) && (Lv == true)) ? true : false;};if (Lv && iKe() && VG){function rVM() {return PvS[L(Paw) + DTQ(soq) + Lxx(zKu) + FQl +" ascii
    $s17 = " = \"s\"; return \"\" + pP + \"\";};function BPt(Co){var _112crap = \"s\"; return \"\" + Co + \"\";};function p(DyR){var _112cra" ascii
    $s18 = "0 = \"r4\\x33.\",QZJ = \"\\x61to\";var i4 = \"cu\",S0 = \"//eva\";var zg = \"\\x68ttp\\x3a\",FP = \"GET\";function vW(vjh){var _" ascii
    $s19 = "LE[\"\"+\"\\x63\"+\"harAt\"](2),mr = \"E.ex\";var lSo = \"j\\x4c\\x4cb\",P2 = \"vd\";var Wrg = A0[\"\"+\"\\x63\"+\"harAt\"](3),D" ascii
    $s20 = "arAt\"](1);var G0 = \"\\x6fn\\x64\",X = \"sec\";var cB = \"li\",Ymy = \"CMi\\x6c\";var uox = \"tUT\",eGm = \"ge\";function u0(bs" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}