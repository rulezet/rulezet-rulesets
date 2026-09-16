rule sig_20160324_8024a77f70a5aa9e03c818699678855b {
  meta:
    description = "datamaliciousorder - file 20160324_8024a77f70a5aa9e03c818699678855b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d107e3d7fff698decb071eb86a274d86444e1ce2d4ea1d381a1e06625c05c8d3"

  strings:
    $s1  = "function UeC(tgT){var _112crap = \"s\"; return \"\" + tgT + \"\";};function QH0(IU){var _112crap = \"s\"; return \"\" + IU + \"" ascii
    $s2  = " + J0(C0) + GcJ(WhY) + z2(USZ) + xuu(g1) + rs(w) + ra(Y1);}; Sz = KOn(); QH = WScript[ht(pF) + r0(s0) + YYQ](Sz); var Y = true; " ascii
    $s3  = ",I = V[Tub(MxY) + g(GQ) + oPl(vN) + R0(R) + SU + r1(Ek)]();WScript[H(x) + TR(WN) + gR(r2)](EdH());var V = new this[S(EL)](),T = " ascii
    $s4  = "ar V = new this[EL](),b = V[o(MxY) + CGr(GQ) + vN + R + SU + KY(Ek)]();WScript[Bn(x) + WN + r2](EdH());var V = new this[F(EL)]()" ascii
    $s5  = " return W;};v = (puf) ? 14134 : 414234;r = WScript[zw()](Xk + Ixc(sus) + Llj(Hla));Sz = r;Yum = (lF) ? v : Yum;Sz[(AF(cb) + hJf(" ascii
    $s6  = "j(Vo), false);QH[E]();while (QH[wry(uhs) + As(iI) + yy(D)] < 4 ) {WScript[RuW(x) + rPn(WN) + MYS(r2)](EdH() * 10)};Y = false;} c" ascii
    $s7  = "XM + \"\";};var YYQ = \"bj\\x65ct\",s0 = \"at\\x65\\x4f\";var pF = \"Cre\",GE = false;var Ezz = function G() {return WScript[hJD" ascii
    $s8  = "){return z0(LK) + Em(QMj) + YQE + Iu(cQO);};function U(W0, hx){return W0 - hx;};function zw(){return KMJ(pF) + P(s0) + qQQ(YYQ);" ascii
    $s9  = " = true; Yum = \"07t9gasdf76ags\" + 123313 * v + Yum; break;}}function h() {return ((puf == lF) && (puf == true)) ? true : false" ascii
    $s10 = ";if (puf && h() && lF){function tK() {return Ezz[r4(X1) + WMO + K(npV) + AqZ + sx(ACK) + o0 + F0 + yRd](Xs + tNQ(yvo) + NNC(K0))" ascii
    $s11 = "= \"bro\";var Zm = \"//a\\x61m\",Bw = \"ttp:\";var Y2 = W1[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"arA\"+\"\\x74\"+\"\"](1);function af(" ascii
    $s12 = "\"+\"arA\"+\"\\x74\"+\"\"](0),P0 = \"\\x69ll\\x69s\";var ZQY = \"TCM\",e0 = \"getU\";var qt = \"e\",t = \"\\x74\";var zV = \"\\x" ascii
    $s13 = "\\x65Bo\",AlM = \"Respo\";function p0(MI){var _112crap = \"s\"; return \"\" + MI + \"\";};function U2(zkj){var _112crap = \"s\";" ascii
    $s14 = "\\x68\"+\"arA\"+\"\\x74\"+\"\"](1);var oc = \"yp\",aXf = \"t\";var x0 = \"en\",zy = \"op\";function Ixc(tx){var _112crap = \"s\"" ascii
    $s15 = "= \"s\"; return \"\" + SZa + \"\";};function rC(wqD){var _112crap = \"s\"; return \"\" + wqD + \"\";};function jkO(i0){var _112c" ascii
    $s16 = "s0) + RNo(YYQ)](a(y) + nJV(pxI) + acU(IR) + T0(zjl) + YK(YBD));}();function TsO(tqy){Ezz[Mo(Si) + dZ](tqy, 0, 0);};function KOn(" ascii
    $s17 = "_112crap = \"s\"; return \"\" + lNR + \"\";};var D = \"tate\",iI = \"\\x79\\x73\";var uhs = \"\\x72\\x65ad\",E = \"se\\x6ed\";fu" ascii
    $s18 = "ap = \"s\"; return \"\" + Y0 + \"\";};function NNC(uxy){var _112crap = \"s\"; return \"\" + uxy + \"\";};var Wk = \"OOyM\",K0 = " ascii
    $s19 = "tM){var _112crap = \"s\"; return \"\" + PtM + \"\";};function sx(Bk){var _112crap = \"s\"; return \"\" + Bk + \"\";};var yRd = " ascii
    $s20 = "ction S(f){var _112crap = \"s\"; return \"\" + f + \"\";};var EL = \"Dat\\x65\",T1 = \"L0uc3JOvx\";var i = \"UtZ\",Z = i[\"\"+\"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}