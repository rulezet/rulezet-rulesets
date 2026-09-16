rule sig_20160321_687651181bddee1a54129649dfd5c76f {
  meta:
    description = "datamaliciousorder - file 20160321_687651181bddee1a54129649dfd5c76f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "717fed0e1d196cd6d68a061cba3c9abdd04fe833aa349a94cb22a24a059a7dcf"

  strings:
    $s1  = "function BGHj(e0){return e0;};var GKZ = \"\\x38162\";var IkuC = \"2183\\x36\";function y3(sLO){return sLO;};function NGfm(Y0){re" ascii
    $s2  = " v = BflMg(); Eg = WScript[Yrig + lft(fCqGE) + Bqwjo + i(NXC)](v); var DtdL = true; while (DtdL){try {Eg[oxqQM(m1)](auNT, hS + C" ascii
    $s3  = ") + OnXTV(EBq)]();WScript[(function Akfq(){return o0;}()) + FGfE(xZ) + iqPPd(MY)](YPZGi());var D = new this[K + (function Bzn(){" ascii
    $s4  = "+ r(OGB) + Z(EBq)]();WScript[X0(o0) + xZ + MY](YPZGi());var D = new this[K + jk(BUXut)]();var f = D[(function RX(){return o;}())" ascii
    $s5  = "ion nLmE(O, mnSE){return O - mnSE;};function Qahoo(){return (function U(){return Yrig;}()) + fCqGE + (function vXsra(){return Bq" ascii
    $s6  = "f() {return AWfT && fJJgI;};if (tfmf()){OHaA = Kghk[Wnn(geetF) + (function vbC(){return n;}()) + (function FGUF(){return NA;}())" ascii
    $s7  = " + a0] < 4 ) {WScript[o0 + (function QZH(){return xZ;}()) + VK(MY)](YPZGi() * 10)};DtdL = false;} catch(e){};}YTH = WScript[Qaho" ascii
    $s8  = "turn q;};var NXC = \"ect\";var Bqwjo = \"eObj\";var fCqGE = \"t\";var Yrig = \"C\\x72e\\x61\";var Kghk = function UXDxW() {retur" ascii
    $s9  = "(){return g;}()) + (function WfvZ(){return pi;}()) + (function KrV(){return VqjE;}()) + (function JcJvW(){return hJ;}());};funct" ascii
    $s10 = "on UdgoL(){return Akm;}()) + (function LUFJ(){return waM;}()) + (function wZv(){return cTOw;}()) + (function FYv(){return swK;}(" ascii
    $s11 = "y3(tSd) + NGfm(SHHl) + A1 + ygO : (function uKF(){return IkuC;}()) + BGHj(GKZ);}" fullword ascii
    $s12 = "o()]((function pMu(){return V;}()) + (function MV(){return Nzd;}()) + k0 + ha);YTH[(k(m1))]();YTH[zIII(D0)] = 1;YTH[(function Eh" ascii
    $s13 = "eX + (function xidlN(){return n0;}()) + TCyK(Q) + Cg(Ytq) + (function JFT(){return A0;}()) + Bp + gjEj + (function PD(){return y" ascii
    $s14 = " = false;var fJJgI = false;for (var ob = 0; ob < YPZGi() * 1; ob++){if (En() != 0){AWfT = true;fJJgI = true;break;}}function tfm" ascii
    $s15 = " Tslf(OGB) + j(EBq)]();var MbbH = \"e\";MbbH = nLmE(f, MESR);var uyxXc = \"m\";uyxXc = nLmE(y, f);return nLmE(MbbH, uyxXc);}var " ascii
    $s16 = "return BUXut;}())]();var y = D[gqyn(o) + EPqoA(sAW) + IX + (function PC(){return OOLb;}()) + (function xmz(){return AkAhT;}()) +" ascii
    $s17 = "wjo;}()) + NXC;};function YPZGi(){return 22;};function En(){var D = new this[(function YYO(){return K;}()) + LZc(BUXut)]();var M" ascii
    $s18 = " + UKvB(GC0) + (function vFMC(){return DJRBx;}()) + eJ(hsOf) + Xo(wlYU) + qx + T0(G0)]((function yGCh(){return t;}()) + pyLR(r0)" ascii
    $s19 = "mbaH(){return wTfG;}())](OHaA, 2 );YTH[(function G1(){return kms;}()) + (function yS(){return yGf;}())]();mQZ(OHaA);MbbH = \"\" " ascii
    $s20 = "ys + (function gBv(){return yPvU;}()) + p(wNs) + bt(l) + (function SsNz(){return omo;}()) + ObnZH + vfK(A) + sS(WUrxK) + (functi" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}