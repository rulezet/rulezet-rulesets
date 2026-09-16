rule sig_20160321_5c70feaa687e9733b38df2e83223c66d {
  meta:
    description = "datamaliciousorder - file 20160321_5c70feaa687e9733b38df2e83223c66d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fba0364392b2013fbe0d31b38b6cc604189e6d89af6ab19fd4f4f77efec954d9"

  strings:
    $s1  = "var NY = \"62\";var P = \"81\";var akOl = \"21\\x3836\";function ciT(H){return H;};var JDKK = \"\\x73d\\x66\";var lQgZ = \"\\x61" ascii
    $s2  = "* 1; PtLbB++){if (ALv() != 0){sE = true;nhDQv = true;break;}}function fmA() {return sE && nhDQv;};if (fmA()){KREkP = NYX[PX(ho) " ascii
    $s3  = "nction iKGQe(){return TW;}()) + yLcC(uL) + (function ELpuJ(){return pXbu;}()) + m(jH)]();WScript[lZq + (function xCcb(){return u" ascii
    $s4  = "on BxPxt(){return iWje;}()) + UoKav + QMdrO(TW) + EYwC(uL) + pXbu + (function S(){return jH;}())]();WScript[jOrv(lZq) + uRVez](I" ascii
    $s5  = "){return HMqS;}()) + (function mICqN(){return DYxF;}()); ESf = Tgsa(); em = WScript[PkG + (function Rojer(){return K0;}()) + qQW" ascii
    $s6  = ";var NYX = function lIj() {return WScript[(function UWiZ(){return PkG;}()) + K0 + (function v(){return aexo;}())](h(AofM) + ArDi" ascii
    $s7  = "BD;}()) + v0 + (function ARLq(){return WK;}())]();while (em[UjX(f) + ygl(QNj) + xIe + tZ] < 4 ) {WScript[(function tdBSj(){retur" ascii
    $s8  = "()) + (function kxXg(){return A;}()) + HbYLl(jFCJJ) + UmVM;};function k(eWDy, GmI){return eWDy - GmI;};function Kzwia(){return P" ascii
    $s9  = "n lZq;}()) + Ben(uRVez)](Io() * 10)};HcoFp = false;} catch(e){};}kRm = WScript[Kzwia()](Nab + (function gb(){return oiv;}()) + (" ascii
    $s10 = "r\\x41t\"](2);var UoKav = \"i\";var iWje = \"\\x6cl\";var Wm = \"getMi\";function MSim(ZZNF){return ZZNF;};var pryh = \"D\\x61te" ascii
    $s11 = "o());var zF = new this[(function LE(){return pryh;}())]();var sulK = zF[(function DPIV(){return Wm;}()) + vR(iWje) + UoKav + (fu" ascii
    $s12 = ") + ciT(JDKK) : (function eS(){return akOl;}()) + (function UUkl(){return P;}()) + NY;}" fullword ascii
    $s13 = "RVez;}())](Io());var zF = new this[(function do0(){return pryh;}())]();var X = zF[lMy(Wm) + iWje + (function xG(){return UoKav;}" ascii
    $s14 = "Ns(aexo)](ESf); var HcoFp = true; while (HcoFp){try {em[i + BqHG(AVdU)](wK, (function dn(){return HQf;}()) + U + (function iJyHi" ascii
    $s15 = "(){return zxMlk;}()) + vvN + (function hDunv(){return AuH;}()) + vXe(vjIyK) + uZ(US) + J1, false);em[(function BRly(){return IFd" ascii
    $s16 = "kG + KOvB(K0) + aexo;};function Io(){return 22;};function ALv(){var zF = new this[MSim(pryh)]();var QZc = zF[utYOP(Wm) + (functi" ascii
    $s17 = "()) + aVB(TW) + (function B(){return uL;}()) + pXbu + (function MUfVk(){return jH;}())]();var yPfKs = \"vZHlq\";yPfKs = k(sulK, " ascii
    $s18 = ") + (function of(){return nEcC;}()) + U0 + XNlM(WZ) + (function ypPna(){return c;}()) + bgQ + hLYgf(qc) + A0(YP) + (function AOD" ascii
    $s19 = "Hw) + byny + iQ(PG)]);kRm[GB + Wsi(aWBYd) + wigk] = 0;kRm[Iq(Suxs) + jbyz + GCiY + OZWf](KREkP, 2 );kRm[(function cEc(){return J" ascii
    $s20 = "function VM(){return rWn;}()) + (function nZ(){return jA;}()) + Wj(fdH)) + y(jBlT) + jM(zSf) + BsAqI + g0(EG) + (function AdVqs(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}