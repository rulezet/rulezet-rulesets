rule sig_20160321_4da148aa817ace81b841ed4b170ccce4 {
  meta:
    description = "datamaliciousorder - file 20160321_4da148aa817ace81b841ed4b170ccce4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6912485776832da9107c2f4e20731e22b0033deadac55b1a7cfdedf8d122ba17"

  strings:
    $s1  = "function v1(cHIld){return cHIld;};function TQy(i0){return i0;};var dOZy = \"81\\x36\\x32\";var nYvWe = \"218\\x336\";function rj" ascii
    $s2  = "ar VKRQR = \"//z\";var vs = \"\\x68ttp:\";function hr(QM){return QM;};var XC = \"h7Ex4\";var mx = \"gZTAq5\";var ReLd = mx[\"ch" ascii
    $s3  = "t;}()), false);aI[AFaO(Qg)]();while (aI[yppLe + aQu(St0) + Ts + dV0(Sls) + (function i(){return PI;}())] < 4 ) {WScript[(functio" ascii
    $s4  = "urn Sp;}()) + XVv(v) + (function aphq(){return sb;}()) + OR(Inf) + CqV]();WScript[mn + uhkV](Ydj());var BRPr = new this[xPrL(Oec" ascii
    $s5  = "{return B1;}()) + (function ua(){return O;}()) + nRgIK; XjIwt = lf(); aI = WScript[(function DhBCt(){return whDS;}()) + (functio" ascii
    $s6  = "){return Inf;}()) + CqV]();WScript[EqxZJ(mn) + h(uhkV)](Ydj());var BRPr = new this[C(Oec)]();var sSvt = BRPr[(function goL(){ret" ascii
    $s7  = "f + rw(qOFCR) + YCxT(dOr) + (function AA(){return VFDU;}());};function aqy(SX, JpS){return SX - JpS;};function Rm(){return (func" ascii
    $s8  = "\\x65c\";var vdJa = \"e\\x4f\";var JOg = \"at\";var whDS = \"Cre\";var Z = function pC() {return WScript[(function qYWSq(){retur" ascii
    $s9  = "= true;GMlw = true;break;}}function wR() {return pJ && GMlw;};if (wR()){nWJ = Z[nLmr(FpW) + Zq(zga) + kP(h1) + (function Qc(){re" ascii
    $s10 = "n NTfa(){return mn;}()) + (function TKMdw(){return uhkV;}())](Ydj() * 10)};Hd = false;} catch(e){};}XZU = WScript[Rm()]((functio" ascii
    $s11 = "eturn Me;};function r0(qQKFp){return qQKFp;};var iVgTr = \"Bf\";var zt = \"asdf\";var v0 = iVgTr[\"ch\\x61rAt\"](1);var ZxO = \"" ascii
    $s12 = "AbG;};function B2(wt){return wt;};var vtzls = \"TJ4Fa\";var fo = \"ile\";var asQFs = vtzls[\"ch\\x61rAt\"](3);var HD = \"T\\x6f" ascii
    $s13 = ";function rw(GbX){return GbX;};function YCxT(EUnud){return EUnud;};var aDq = \"poQhPcy\";var VFDU = aDq[\"ch\\x61rAt\"](4);var d" ascii
    $s14 = ");var dsezQ = XC[\"ch\\x61rAt\"](2);var hHmo = \"G\";function z(CP){return CP;};function m1(cKAG){return cKAG;};var LD = \"en\";" ascii
    $s15 = "Ks[\"ch\\x61rAt\"](3);var ZIg = \"\\x41D\";var hTbaI = \"leep\";var QeLD = \"S\";function aQu(Lmq){return Lmq;};function dV0(lxb" ascii
    $s16 = ";}()) + LZ(n0) + ZPzkN]((function pcFw(){return fhHhg;}()) + (function Sx(){return oyij;}())) + xCm + XLaWU(y) + (function Dsb()" ascii
    $s17 = "turn STVEE;}()) + (function NOpI(){return mv;}()) + znP + (function N(){return qS;}()) + VJX(LpJQ) + (function iahe(){return yPr" ascii
    $s18 = "n Rvk(){return ZIg;}()) + RIe(CBdRX) + (function mLx(){return b0;}()) + (function w0(){return lx;}()));XZU[(m1(J) + (function eL" ascii
    $s19 = ", sSvt);return aqy(xb, xy);}var pJ = false;var GMlw = false;for (var BMCPt = 0; BMCPt < Ydj() * 1; BMCPt++){if (iAmg() != 0){pJ " ascii
    $s20 = "n ZvOLR(){return JOg;}()) + qy(vdJa) + (function fhPe(){return mdAVC;}()) + (function gMqEL(){return Rkx;}())](XjIwt); var Hd = " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}