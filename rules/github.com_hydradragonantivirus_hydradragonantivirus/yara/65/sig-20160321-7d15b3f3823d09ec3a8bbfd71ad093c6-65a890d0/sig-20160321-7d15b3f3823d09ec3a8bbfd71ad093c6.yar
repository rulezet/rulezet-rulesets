rule sig_20160321_7d15b3f3823d09ec3a8bbfd71ad093c6 {
  meta:
    description = "datamaliciousorder - file 20160321_7d15b3f3823d09ec3a8bbfd71ad093c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ab9a1a350dee3aab6c80a82fb90a21b1951750b89a0dc7796b17776aa8c2d9a"

  strings:
    $s1  = "function W2(RZ){return RZ;};var I0 = \"\\x3816\\x32\";var NW = \"1836\";var zBD = \"\\x32\";function ILwGd(AY){return AY;};funct" ascii
    $s2  = "(function z(){return jn;}()) + CSCCE + (function rGPg(){return QG;}())]();WScript[PY(kidPv) + JmZ(fnX) + hgqB](auadL());var s = " ascii
    $s3  = "p;};function YTUz(tFw){return tFw;};function lqBP(Ij){return Ij;};var Kn = \"89c\\x64\";var qMKH = \"nqw\";var hguze = \".com\\x" ascii
    $s4  = " = lq(); i = WScript[cWb(UuxXM) + (function hYQxK(){return pWc;}()) + MFHz](gRUH); var fvHB = true; while (fvHB){try {i[(functio" ascii
    $s5  = "turn CSCCE;}()) + (function Z0(){return QG;}())]();WScript[v0(kidPv) + fnX + (function JXU(){return hgqB;}())](auadL());var s = " ascii
    $s6  = "tion l(){return sv;}()) + wS + (function GXzHv(){return DQIY;}())] < 4 ) {WScript[fia(kidPv) + (function LnaBf(){return fnX;}())" ascii
    $s7  = "65\";var VmOV = function k() {return WScript[ekk(UuxXM) + yTNdU(pWc) + OUE(MFHz)](VevvY(WO) + (function boJlV(){return RDBYh;}()" ascii
    $s8  = "y, L){return oWeGy - L;};function Kbt(){return (function KVxSG(){return UuxXM;}()) + AjIh(pWc) + YXL(MFHz);};function auadL(){re" ascii
    $s9  = "zI && lmNI;};if (hM()){dofHJ = VmOV[(function A0(){return DEpCY;}()) + c(oqH) + AHjw(ZloK) + (function PTF(){return Q0;}()) + (f" ascii
    $s10 = " + hgqB](auadL() * 10)};fvHB = false;} catch(e){};}O = WScript[Kbt()](i0 + nMwTc + Capll(fXbD) + sOH(ZOsBg) + BBdjt(vXY));O[((fu" ascii
    $s11 = "ILwGd(cX) + (function Ws(){return csB;}()) + ZVnDB(gKsc) : zBD + (function Xb(){return NW;}()) + W2(I0);}" fullword ascii
    $s12 = "nction AhOs(){return dnu;}()))]();O[yGZwd] = 1;O[(function sAy(){return W1;}()) + I(ATdCu)](i[EF + jiV(h) + DIsmK(h0) + (functio" ascii
    $s13 = "n ejAd(){return RcO;}())]);O[Xhzb(sQdyf) + mJAo(Vn) + (function KjS(){return HTiA;}()) + (function Hmb(){return cpmQe;}()) + pwP" ascii
    $s14 = "unction sk(){return NFZQp;}()) + r(skCTY) + fe + Arup + G0(MLXYJ) + (function o(){return vaCQT;}()) + YUq]((function YF(){return" ascii
    $s15 = "r lmNI = false;for (var SRrb = 0; SRrb < auadL() * 1; SRrb++){if (m() != 0){zI = true;lmNI = true;break;}}function hM() {return " ascii
    $s16 = "turn 22;};function m(){var s = new this[(function RwQDi(){return G;}())]();var Pp = s[vafap + (function Zyp(){return fyh;}()) + " ascii
    $s17 = "new this[(function ChRG(){return G;}())]();var nktB = s[uzxrM(vafap) + (function O0(){return fyh;}()) + jn + (function ApeW(){re" ascii
    $s18 = "turn (function QE(){return iRWN;}()) + LR + Rgfu + (function ruf(){return v;}()) + IowRr(vUTrR) + nlbR(DL);};function DynHR(oWeG" ascii
    $s19 = "new this[Hk(G)]();var DYGAL = s[WRDKx(vafap) + (function d(){return fyh;}()) + jn + (function hvRA(){return CSCCE;}()) + QG]();v" ascii
    $s20 = "n iems(){return dnu;}())](Y0(YG) + (function Zne(){return a;}()), Rk(aAA) + (function yvhQp(){return j;}()) + Fpeo + (function m" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}