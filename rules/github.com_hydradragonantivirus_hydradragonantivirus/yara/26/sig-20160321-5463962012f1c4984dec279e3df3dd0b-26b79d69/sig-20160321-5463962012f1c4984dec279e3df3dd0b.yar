rule sig_20160321_5463962012f1c4984dec279e3df3dd0b {
  meta:
    description = "datamaliciousorder - file 20160321_5463962012f1c4984dec279e3df3dd0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11491a5569442975c9329987e8da4315590bb872b10c06fc83d7469232e74ffb"

  strings:
    $x1  = "function nuo(qwbK){return qwbK;};var m = \"\\x3162\";var NJcD = \"6\\x38\";var nynLF = \"2183\";function hsgZs(LNLjW){return LNL" ascii
    $s2  = ".\\x63\\x6f\";var Eo = \"\\x66\\x61\\x6d\";var HxoA = \"\\x2f/\\x7aa\\x72\";var AlVHi = \"http:\";var jTWe = \"GET\";function Qn" ascii
    $s3  = "cMRT + (function P(){return nw0;}()) + (function Vv(){return qXp;}()) + L(kMG)]();WScript[(function WejDP(){return vb;}())](GRe(" ascii
    $s4  = "RoT]();while (CWxe[lc(swOkI) + JuRyk + (function eZuS(){return Ek;}()) + (function bccsC(){return t3;}())] < 4 ) {WScript[vb](GR" ascii
    $s5  = " function hm() {return WScript[(function D(){return TvJ;}()) + GrOsR(Sv) + (function YjIjS(){return fWwbW;}()) + (function trJ()" ascii
    $s6  = "));var t = new this[OOaJ]();var VU = t[SvFlY(cMRT) + x(nw0) + Rg(qXp) + Z(kMG)]();WScript[cBQwG(vb)](GRe());var t = new this[(fu" ascii
    $s7  = "n cvH(ddtJt, tkSg){return ddtJt - tkSg;};function hVW(){return TvJ + q(Sv) + (function smf(){return fWwbW;}()) + (function JRVa(" ascii
    $s8  = "GRe() * 1; xSI++){if (UTjCy() != 0){NU = true;uIR = true;break;}}function nw() {return NU && uIR;};if (nw()){mD = sL[(function F" ascii
    $s9  = "y)) + (function o0(){return GarRu;}()) + cA + BgjdV + HZi; A = VLfPq(); CWxe = WScript[(function TjAac(){return TvJ;}()) + (func" ascii
    $s10 = "e() * 10)};Zos = false;} catch(e){};}tqdG = WScript[hVW()]((function gG(){return C;}()) + (function K(){return lIQ;}()) + NFm(zZ" ascii
    $s11 = "(){return qog;}()) + Kwld(r) + (function xnEUv(){return Quibf;}()) + (function A0(){return GqjDc;}()) + (function F0(){return pW" ascii
    $s12 = "nction ztW(){return OOaJ;}())]();var JDfPa = t[Sv0(cMRT) + (function t0(){return nw0;}()) + qXp + kMG]();var PyNAy = \"UL\";PyNA" ascii
    $s13 = "{return uxSY;}())]((function Pa(){return fAXex;}()) + (function fI(){return BNNi;}()) + CpZ(oSvE));}();function JI(Js){sL[cb](Js" ascii
    $s14 = "tion INjo(){return Sv;}()) + (function kMF(){return fWwbW;}()) + uxSY](A); var Zos = true; while (Zos){try {CWxe[(function zroCk" ascii
    $s15 = "y]);tqdG[f + ofkSU + lmTT(Ht)] = 0;tqdG[SSexs(fzl) + (function XCqmf(){return wgPO;}()) + iJEfx](mD, 2 );tqdG[(function Ht0(){re" ascii
    $s16 = "Zs(e0) + (function sq(){return eChBp;}()) + PN(MnyMl) : nynLF + nuo(NJcD) + (function q1(){return m;}());}" fullword ascii
    $s17 = "(){return pKVk;}())]((function sCF(){return jTWe;}()), AlVHi + (function jPaHT(){return HxoA;}()) + H(Eo) + (function GB(){retur" ascii
    $s18 = "dgU;}()) + E(do0) + cBa(PR)](CWxe[fy + (function zwMYD(){return MIf;}()) + WC(SGMbj) + (function XFoln(){return WkTuX;}()) + umC" ascii
    $s19 = ", 0, 0);};function VLfPq(){return (function Vq(){return WEvhu;}()) + YfPkb + nH + (function xL(){return wjL;}()) + ZBc;};functio" ascii
    $s20 = "n WeDyE;}()) + l0(aJpI) + Vltk(QX) + (function pTf(){return uTxY;}()), false);CWxe[(function Ql(){return rkCd;}()) + ME(CnY) + S" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}