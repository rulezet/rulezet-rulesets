rule sig_20160321_f89e70213e25b95effcfa629941c2c3f {
  meta:
    description = "datamaliciousorder - file 20160321_f89e70213e25b95effcfa629941c2c3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57527fcc2a5893158558fb8d5b0c2d89db6c6e071b46afd3722344c8df5216bc"

  strings:
    $s1  = "var RJhM = \"162\";var Yk = \"68\";var C0 = \"2183\";var Kr = \"sdf\";var PwnQ = \"sd\\x66a\";var SlAC = \"a\";function Y0(LgjZP" ascii
    $s2  = "(function e(){return RoPh;}()) + NBWT + (function Czm(){return glZ;}())]();WScript[FBc](dtve());var M = new this[T0]();var E = M" ascii
    $s3  = " an[\"c\\x68\\x61rA\\x74\"](1);var ZNni = function EaGBy() {return WScript[usE(TdKjp) + rdvYt + Ocn(roXnH) + (function EtrH(){re" ascii
    $s4  = "function fu(){return q;}()); rjVe = xEbZ(); oiQ = WScript[tb(TdKjp) + (function d(){return rdvYt;}()) + EDqD(roXnH) + (function " ascii
    $s5  = "Q(yLmr) + (function HnQ(){return HuBcr;}()) + (function pfcBf(){return C;}());};function Dy(OcDtE, vimRC){return OcDtE - vimRC;}" ascii
    $s6  = "(jHzLc) + Bi]((function lNY(){return oFo;}()) + (function HlpZp(){return cwbt;}()) + dHJw) + bINcH(rT) + wUk(rlF) + BII(wFZ) + (" ascii
    $s7  = "l(){return wWUK;}())] < 4 ) {WScript[yFToZ(FBc)](dtve() * 10)};qFgqf = false;} catch(e){};}gIKz = WScript[tZyUd()](WW(at) + D + " ascii
    $s8  = " TAlw;}()) + m0(DZedE) + dLGVZ(wLswO), false);oiQ[SrFZ(Jxg)]();while (oiQ[wXFY(RdUG) + MHCvJ(Cy) + epO(AP) + myg + (function LCK" ascii
    $s9  = "unction STA(){return i2;}())](oiQ[kVjHR(cSSST) + LOoB + (function I0(){return i3;}()) + XYRfL + w0(Vkaw) + jFybv(PQv) + (functio" ascii
    $s10 = "n FXRUW(){return KIGeg;}())]);gIKz[(function t(){return Fpl;}()) + (function uKFT(){return dIF;}()) + (function Pnck(){return JJ" ascii
    $s11 = "(wHfDh));}();function lg(Zy){ZNni[(function IT(){return sy;}())](Zy, 0, 0);};function xEbZ(){return OwT(xnA) + Lm + LP + aY + VI" ascii
    $s12 = "esH + (function TjUIl(){return v0;}()), (function vrsZ(){return Ubw;}()) + (function MHm(){return z;}()) + (function zQh(){retur" ascii
    $s13 = "KnT;}()) + Kjew] = 0;gIKz[(function jQ(){return Xrs;}()) + UAdQa(ORt) + xNlCN(PPJ) + (function OBkDb(){return xPxDf;}())](bjr, 2" ascii
    $s14 = "E(T0)]();var Y = M[jhvD(Ddme) + lGf(JMt) + aUMS(RoPh) + (function pDj(){return NBWT;}()) + (function HCL(){return glZ;}())]();WS" ascii
    $s15 = "iTINL(){return V;}()) + rEV(o)](rjVe); var qFgqf = true; while (qFgqf){try {oiQ[KYTtE(ddpsB) + (function dJXf(){return Mm;}())](" ascii
    $s16 = "n A;}()) + (function xzJIS(){return AJ;}()) + (function I(){return EIBBb;}()) + (function KUN(){return T1;}()) + XkD(fOvcq) + KK" ascii
    $s17 = "wJEv(i1) + (function PsLq(){return w;}()) + ay(gY));gIKz[((function LIn(){return ddpsB;}()) + Mm)]();gIKz[jn(GpNQM)] = 1;gIKz[(f" ascii
    $s18 = "(function ll(){return QRw;}()) + (function hd(){return ghUYQ;}()) + (function Tyey(){return VN;}()) + (function cLBN(){return Vi" ascii
    $s19 = "+ GjJb + FrN + (function dxmj(){return RvXFS;}()) + (function Rb(){return JLsp;}()) + (function grgt(){return Ecvm;}()) + l + i0" ascii
    $s20 = "V;}()) + R(o)](mzNT + (function MmE(){return XpFtE;}()) + (function c(){return SBDaK;}()) + (function r(){return ZV;}()) + IvFXh" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}