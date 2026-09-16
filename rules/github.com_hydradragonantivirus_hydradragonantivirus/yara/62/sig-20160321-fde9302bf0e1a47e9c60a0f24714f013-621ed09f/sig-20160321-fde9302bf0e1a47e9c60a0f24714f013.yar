rule sig_20160321_fde9302bf0e1a47e9c60a0f24714f013 {
  meta:
    description = "datamaliciousorder - file 20160321_fde9302bf0e1a47e9c60a0f24714f013.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e381cf51bc4bdaa0192a163c436821d9083f53149af67c694f61751127535be6"

  strings:
    $s1  = "function pW(xgv){return xgv;};function u0(DyASo){return DyASo;};var U0 = \"Im1fI\";var Se = \"2eo\";var s0 = Se[\"ch\\x61rA\\x74" ascii
    $s2  = "qCd;}())]();WScript[BSr + (function stsm(){return O;}())](kVn());var UwPc = new this[(function eDK(){return G1;}())]();var sJndi" ascii
    $s3  = "(e){};}JZYTG = WScript[ZckC()]((function aW(){return zoV;}()) + (function uRWev(){return zRhhd;}()) + nK(DY) + (function JrF(){r" ascii
    $s4  = "Me = QUb(); T = WScript[SxiAN(UKwzi) + kf(v0) + (function G0(){return Xp;}()) + WlBw](nMe); var CBgt = true; while (CBgt){try {T" ascii
    $s5  = "(function X0(){return Fjl;}()) + Kd + md(txg) + o + (function KET(){return Ve;}()) + (function xlo(){return cqCd;}())]();WScript" ascii
    $s6  = "ction QUb(){return CG + DK(eHG) + cOT(TA) + kbc;};function njkK(B, P){return B - P;};function ZckC(){return LebS(UKwzi) + jk(v0)" ascii
    $s7  = " QFL() {return sWkYa && LJEZr;};if (QFL()){EAFMZ = Vdt[H1(Y) + (function Ug(){return Itsw;}()) + UvKk + (function aY(){return jY" ascii
    $s8  = "r WlBw = N[\"ch\\x61rA\\x74\"](0);var Xp = \"jec\";var v0 = \"te\\x4fb\";var UKwzi = \"\\x43rea\";var Vdt = function v() {return" ascii
    $s9  = "AoI + a + (function Z0(){return ZufDi;}())] < 4 ) {WScript[BSr + (function bi(){return O;}())](kVn() * 10)};CBgt = false;} catch" ascii
    $s10 = " = UwPc[(function Wt(){return Fjl;}()) + zbyxD(Kd) + (function GD(){return txg;}()) + (function ezPPL(){return o;}()) + (functio" ascii
    $s11 = "W0(){return ZNqnV;}()) + ecMY + sWkYa ? Gc + WsrH(Ag) : (function el(){return MUpt;}()) + (function MYqgG(){return OTmAF;}()) + " ascii
    $s12 = "()) + sHhX] = 1;JZYTG[dWu + UqQwB](T[(function mF(){return qept;}()) + (function Dr(){return G2;}()) + (function PzE(){return aw" ascii
    $s13 = "Q;}()) + k + PKIKE(Yp), false);T[(function cRqHq(){return yBFt;}())]();while (T[(function Jp(){return dS;}()) + MsWm(jwkYE) + cU" ascii
    $s14 = ";}()) + dCx(U) + JBAV(gD) + l(UhHP)]);JZYTG[idMXX(bs) + (function AjbRq(){return fSGjq;}())] = 0;JZYTG[c0(M) + cqpeP(vLjy) + whA" ascii
    $s15 = "eturn NF;}()));JZYTG[(NNlu(Ov) + (function jJU(){return pxAr;}()))]();JZYTG[SjxIu(w) + zo(EYy) + (function BNqCk(){return VhCB;}" ascii
    $s16 = "jes(nJ) + aBhR(oZ) + rEcd + eu + MeX(x0) + WYLDU(FK) + UF + Tcltr(GHx) + (function Fb(){return K0;}()) + ndkrh(HCX) + (function " ascii
    $s17 = "n CITsw(){return Ve;}()) + JK(cqCd)]();var G = \"K\";G = njkK(Z, d);var dQSS = \"Ea\";dQSS = njkK(sJndi, Z);return njkK(G, dQSS)" ascii
    $s18 = "+ rOsI(ymS) + (function dTn(){return KZtP;}()) + (function yPja(){return CND;}()) + kUs(x) + (function Dnlwn(){return IA;}()); n" ascii
    $s19 = " + (function eZd(){return Xp;}()) + P0(WlBw);};function kVn(){return 22;};function pbw(){var UwPc = new this[G1]();var d = UwPc[" ascii
    $s20 = "Oc + jcu(Jl)](EAFMZ, 2 );JZYTG[(function TZ(){return Q;}()) + (function DfT(){return aP;}())]();hISu(EAFMZ);G = \"\" + Nzv(BFb) " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}