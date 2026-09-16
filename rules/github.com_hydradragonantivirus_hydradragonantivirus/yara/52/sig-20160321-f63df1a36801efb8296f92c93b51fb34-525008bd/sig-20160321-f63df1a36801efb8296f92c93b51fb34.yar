rule sig_20160321_f63df1a36801efb8296f92c93b51fb34 {
  meta:
    description = "datamaliciousorder - file 20160321_f63df1a36801efb8296f92c93b51fb34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4ce6e19e196f3a6abe0269f4c026d2c6b15232976b268b052c88ef6a6761fe1"

  strings:
    $s1  = "function OIbNH(lSl){return lSl;};function YV(QRYy){return QRYy;};var K1 = \"62\";var xgQ = \"68\\x31\";var DUFG = \"218\\x33\";v" ascii
    $s2  = "\\x62\";var QXAQ = \"\\x65a\\x74e\";var h = \"Cr\";var QQ = function R() {return WScript[IhYyr(h) + (function uil(){return QXAQ;" ascii
    $s3  = "tB(){return xZZhF;}()) + (function bQy(){return VdQb;}()) + (function cHO(){return x;}())] < 4 ) {WScript[kYV + uDdWP](VEPg() * " ascii
    $s4  = "(function fFWOW(){return p;}())]();WScript[(function xnivl(){return kYV;}()) + uDdWP](VEPg());var XEUh = new this[(function Syr(" ascii
    $s5  = " + f(p)]();WScript[(function PzQ(){return kYV;}()) + (function afS(){return uDdWP;}())](VEPg());var XEUh = new this[(function xy" ascii
    $s6  = "rn ADnfA;}()) + (function QJ(){return o;}());};function AfCm(dRVHD, loFSN){return dRVHD - loFSN;};function vg(){return (function" ascii
    $s7  = "zM < VEPg() * 1; SgzM++){if (G() != 0){mxfy = true;jSUe = true;break;}}function tN() {return mxfy && jSUe;};if (tN()){smHF = QQ[" ascii
    $s8  = "10)};JUUEo = false;} catch(e){};}P = WScript[vg()](d(Shon) + (function mXc(){return DZOK;}()) + xE(ohos) + onC);P[((function l0(" ascii
    $s9  = " fKA(){return h;}()) + QXAQ + FJ(LyL) + (function Nf(){return y;}()) + yIUp(yg);};function VEPg(){return 22;};function G(){var X" ascii
    $s10 = "pt[xhRh(h) + KNVr(QXAQ) + (function kU(){return LyL;}()) + aES(y) + (function e(){return yg;}())](wSH); var JUUEo = true; while " ascii
    $s11 = "ion rs(){return ls;}()) + mxfy ? (function mW(){return eoaD;}()) + G0 : OIbNH(DUFG) + YV(xgQ) + K1;}" fullword ascii
    $s12 = "(JUUEo){try {N[f1(mwStl)](IPP(RJbp), jvL(T0) + sVR(l1) + (function yI(){return EyY;}()) + BAwr + Wm(GZDkQ) + A0(qN) + (function " ascii
    $s13 = "zxd(){return rc;}()), false);N[(function RH(){return k0;}()) + ctxRh(D)]();while (N[(function tX(){return e0;}()) + (function gb" ascii
    $s14 = "ction n0(){return fJ;}()) + ZQE + ADw(pZ) + (function DrET(){return SCh;}()) + Bm + (function T1(){return YM;}()) + (function S(" ascii
    $s15 = "EUh = new this[(function MVVc(){return DFqu;}())]();var k = XEUh[ax(VbAz) + (function uPC(){return acyV;}()) + oinCu(Yjk) + VMMC" ascii
    $s16 = "yL + Ika(y) + yg]((function K(){return Dtci;}()) + nQQDJ(jtvxw) + (function gqg(){return dSbDq;}()) + uK + (function jmlo(){retu" ascii
    $s17 = ";}()) + (function UDgsq(){return u;}()) + KjeCD(XEiBr)](smHF, 2 );P[ex + h0]();UTTLb(smHF);uVA = \"\" + eogrx(JCnx) + xSLaI + (f" ascii
    $s18 = "\\x74e\";var F = \"b\\x6aect\";var l = \"\\x61\\x74eO\";var sx = \"\\x43r\\x65\";function XfaTu(ZYTK){return ZYTK;};var o = \"LH" ascii
    $s19 = "(function b(){return WqBJU;}()) + wu + LEJzZ + SOx + nvg(eiRS) + Glph + bcZAI(DLU) + ffhnZ](iAHNE(Ey) + A + (function hXcI(){ret" ascii
    $s20 = "urn xG;}())) + QaUXK + WqAPY(Yxa) + VY + mnlG(t0) + io(U) + pRC(PJZzV) + (function ZT(){return QjZt;}()); wSH = Jto(); N = WScri" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}