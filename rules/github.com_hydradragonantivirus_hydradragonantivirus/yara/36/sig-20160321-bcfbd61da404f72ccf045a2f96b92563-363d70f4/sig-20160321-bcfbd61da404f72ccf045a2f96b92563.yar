rule sig_20160321_bcfbd61da404f72ccf045a2f96b92563 {
  meta:
    description = "datamaliciousorder - file 20160321_bcfbd61da404f72ccf045a2f96b92563.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fef2763dbd714c967e0016107a20f921628e5ae22cb3f09d6fafea8e5b1cae59"

  strings:
    $s1  = "function Cw(hCZh){return hCZh;};var HM = \"2b\";var slj = HM[\"c\\x68a\\x72\\x41t\"](0);var NEE = \"\\x316\";var IvVw = \"\\x38" ascii
    $s2  = "wOnF(ZaOn)] < 4 ) {WScript[vF(Lke) + (function jX(){return H;}()) + MGb(bCqbM) + (function xaAT(){return Prc;}())](kCW() * 10)};" ascii
    $s3  = "Script[gZ(mFb) + (function Q(){return YrLfV;}()) + ZiZSa(gKd)](QW(FXM) + r(Q0) + Nlq + VjtL + (function hd(){return liZc;}()) + " ascii
    $s4  = "(function Y(){return V;}()) + kdKQD(sc) + NQ + (function klNeF(){return Xaj;}()) + Hh(Sj)]();WScript[PHa(Lke) + IFm(H) + QT(bCqb" ascii
    $s5  = "WScript[Lke + reHpa(H) + uCDAr(bCqbM) + VoLyk(Prc)](kCW());var b = new this[R0(cJs)]();var RO = b[DRy(rOaG) + PG(vZxh) + zeCw + " ascii
    $s6  = "n dzxr;}()) + kzIKR; tAsfl = Dxg(); HCPuW = WScript[fnaBG(mFb) + jH(YrLfV) + RKP(gKd)](tAsfl); var abtSX = true; while (abtSX){t" ascii
    $s7  = "MvD) + L(xLRS) + (function MPX(){return OyHD;}()) + ne;};function nkm(PhwPC, ppdoZ){return PhwPC - ppdoZ;};function itC(){return" ascii
    $s8  = " 0; J < kCW() * 1; J++){if (TV() != 0){sABCZ = true;qHLt = true;break;}}function eaNUt() {return sABCZ && qHLt;};if (eaNUt()){iV" ascii
    $s9  = "abtSX = false;} catch(e){};}pTHkx = WScript[itC()]((function XRV(){return ZxR;}()) + (function fJY(){return Hlt;}()) + eI(pk) + " ascii
    $s10 = "(zeCw) + Fyot(V) + sc + (function xdWl(){return NQ;}()) + (function xjzsd(){return Xaj;}()) + (function LYJ(){return Sj;}())]();" ascii
    $s11 = "tBZ(bV) + kM);pTHkx[((function aNqg(){return c;}()) + (function R1(){return Qyh;}()))]();pTHkx[UFvv + (function uLjHL(){return F" ascii
    $s12 = "R = SI[(function t(){return zrCF;}()) + aO(cKT) + Eu + (function G1(){return Gpyv;}()) + IG + (function jQm(){return s0;}()) + x" ascii
    $s13 = " (function JHdE(){return y;}()) + NBpmO + MZQR(hyWi) + VzrQ(m) + (function utwL(){return Qrs;}()) + (function zP(){return eIu;}(" ascii
    $s14 = ")) + dTl, false);HCPuW[(function kQa(){return OvoAn;}())]();while (HCPuW[ruG + jQN(HpFQV) + (function QATVf(){return Ti;}()) + H" ascii
    $s15 = "{return I0;}()) + (function Pzc(){return siQh;}()) + bJM(WH) + sABCZ ? Zie(MY) + (function Zzi(){return AtECP;}()) + becMz(VN) :" ascii
    $s16 = " Cw(f1) + (function qbtgi(){return IvVw;}()) + NEE + (function n0(){return slj;}());}" fullword ascii
    $s17 = "+ (function jDfmC(){return V;}()) + (function i(){return sc;}()) + (function Fmm(){return NQ;}()) + Xaj + p1(Sj)]();var Cu = \"r" ascii
    $s18 = "Bd(UTi) + (function Gc(){return u;}())]((function bFrX(){return wMaD;}()) + u0(S)) + hJqY(ZA) + Vnx(J0) + (function cxMp(){retur" ascii
    $s19 = " = new this[(function SN(){return cJs;}())]();var Uj = b[(function f(){return rOaG;}()) + (function dkKrL(){return vZxh;}()) + N" ascii
    $s20 = " (function ilw(){return mFb;}()) + wNpu(YrLfV) + (function OK(){return gKd;}());};function kCW(){return 22;};function TV(){var b" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}