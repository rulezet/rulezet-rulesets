rule sig_20160321_d7b4f83eb7063de4842e1f7733860a04 {
  meta:
    description = "datamaliciousorder - file 20160321_d7b4f83eb7063de4842e1f7733860a04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a14b91b54526d8dea70e868cfd80ae687c8a5a5023f6ea8131cea809dccee71"

  strings:
    $s1  = "function mAVA(EHbk){return EHbk;};function u(xk){return xk;};function dUQn(ZvXI){return ZvXI;};var I0 = \"8XhwUs\";var G = \"2\"" ascii
    $s2  = " new this[xSD(qb)]();var B = gD[(function gKWV(){return Et;}()) + g + eAA + g0(NDa)]();WScript[(function IRAFp(){return Ji;}())]" ascii
    $s3  = "Fe + Q(h) + (function g1(){return VPV;}()) + (function XFp(){return LwI;}())] < 4 ) {WScript[Ow(Ji)](VWH() * 10)};kI = false;} c" ascii
    $s4  = "atch(e){};}z = WScript[bLU()](l(VlbkA) + (function wYgW(){return IaP;}()) + (function w0(){return jBv;}()));z[((function ZyT(){r" ascii
    $s5  = " + (function V(){return g;}()) + (function azX(){return eAA;}()) + NDa]();WScript[(function L0(){return Ji;}())](VWH());var gD =" ascii
    $s6  = "rn IWG - WiaEV;};function bLU(){return Wo + (function i(){return Fk;}()) + (function Fnxpr(){return WZA;}()) + (function Ti(){re" ascii
    $s7  = "pD() {return kNB && nPIrE;};if (hpD()){SZAtn = QoZ[BzBtX + KX(U) + (function djmNj(){return Mqwta;}()) + (function eW(){return z" ascii
    $s8  = "\"se\\x63\";var g = \"l\\x6ci\";var Et = \"getMi\";function xSD(Begiv){return Begiv;};var qb = \"D\\x61\\x74\\x65\";var I = \"fj" ascii
    $s9  = "D(){return H1;}()) + DIgU(XKpDg) + (function sU(){return RB;}()) + Tina(mqWAe) + (function fTyCn(){return Zw;}()) + HEVx(wnS) + " ascii
    $s10 = "r kNB = false;var nPIrE = false;for (var Uk = 0; Uk < VWH() * 1; Uk++){if (gY() != 0){kNB = true;nPIrE = true;break;}}function h" ascii
    $s11 = "(VWH());var gD = new this[qb]();var MRLF = gD[(function cNbe(){return Et;}()) + (function pvUzP(){return g;}()) + eAA + (functio" ascii
    $s12 = "d) + (function XvX(){return Nje;}()) : mAVA(QcdsK) + u(v1) + dUQn(WaXd) + Jemk + (function C(){return G;}());}" fullword ascii
    $s13 = "+ UWk(E2) + aGJx(VlpU)]);z[(function yQs(){return z1;}()) + LW + (function Zr(){return FZzt;}())] = 0;z[XrNOv(BntAx) + dq + r0](" ascii
    $s14 = "turn zK;}()) + Fpz;};function VWH(){return 22;};function gY(){var gD = new this[qb]();var zVL = gD[(function sx(){return Et;}())" ascii
    $s15 = ") + (function Ta(){return zzjP;}()) + bGZLF(XJFQ) + (function EOPoI(){return Z;}()) + l0 + kNB ? ZjH(gXbh) + pKw(UvZm) + jDFk(ar" ascii
    $s16 = "eturn eD;}()))]();z[V0(GKWTf) + rHuh(BBde)] = 1;z[E1(D) + (function KYePu(){return iI;}())](OwoLt[(function aQL(){return y;}()) " ascii
    $s17 = "0;}()) + (function Eso(){return b;}()) + (function HMU(){return wV;}()) + TcBco(a) + WI(qeAs) + (function bM(){return wlds;}()) " ascii
    $s18 = "ipt[vtu(Wo) + (function H0(){return Fk;}()) + WZA + (function P(){return zK;}()) + Fpz](XbZN); var kI = true; while (kI){try {Ow" ascii
    $s19 = "SZAtn, 2 );z[(function tDz(){return eb;}()) + (function DOs(){return jVvi;}()) + SXT(vd)]();ST(SZAtn);GeJN = \"\" + BK(F) + fk(m" ascii
    $s20 = "Llq(ONjj) + (function DOzf(){return yZ;}()) + ArV(nMWXE) + (function QV(){return O0;}()) + dxEB;};function tMtL(IWG, WiaEV){retu" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}