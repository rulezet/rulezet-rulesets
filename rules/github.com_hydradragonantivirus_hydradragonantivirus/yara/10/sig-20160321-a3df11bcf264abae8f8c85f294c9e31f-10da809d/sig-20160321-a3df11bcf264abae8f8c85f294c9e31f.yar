rule sig_20160321_a3df11bcf264abae8f8c85f294c9e31f {
  meta:
    description = "datamaliciousorder - file 20160321_a3df11bcf264abae8f8c85f294c9e31f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f995b4e45bb1bd58d17c1ad7e0fc00fadb38e07f9e2bbbb8d07e6b6499ad3ece"

  strings:
    $s1  = "function nXOe(EL){return EL;};var ZxzKm = \"G2RzmX\";var b1 = ZxzKm[\"char\\x41\\x74\"](1);var dRv = \"3\\x36\\x381\\x36\";var g" ascii
    $s2  = "tion WlRKM(){return piQe;}()) + (function cvHX(){return IH;}())]();WScript[rA + r(y0)](C());var V0 = new this[Cu(cHOZY) + mzv]()" ascii
    $s3  = "ar Q = function loj() {return WScript[jDWM(auto) + (function frNR(){return XysjY;}()) + (function H(){return hsEt;}()) + IppNJ(q" ascii
    $s4  = "unction oREX(){return fF;}()) + QodX(iCybC) + r0(ChxhP) + (function u0(){return HxsI;}()); b = WJNV(); RlRxO = WScript[(function" ascii
    $s5  = ";var L = V0[po(DswF) + y + (function fkMXV(){return DUyii;}()) + xFD + UiJ(piQe) + (function F(){return IH;}())]();WScript[rA + " ascii
    $s6  = "){return nJIAj;}()) + (function FF(){return cZ;}());};function enUk(zu, geun){return zu - geun;};function La(){return CI(auto) +" ascii
    $s7  = " fNR() {return Q0 && h;};if (fNR()){VEcbA = Q[(function t(){return ug;}()) + ZKyGW(B) + (function JxZk(){return TV;}()) + (funct" ascii
    $s8  = "on kknf(){return Lkv;}()) + ifF(IhePL) + bG(zx)] < 4 ) {WScript[rA + y0](C() * 10)};V = false;} catch(e){};}SbxAw = WScript[La()" ascii
    $s9  = "var q = \"get\\x4d\";var AGtN = \"Date\";function r(HTUHl){return HTUHl;};function ajksu(u){return u;};var y0 = \"\\x65\\x70\";v" ascii
    $s10 = "urn GKj;}()) + GS(NHphL))]();SbxAw[xf + jhpN] = 1;SbxAw[SE(ufIF) + (function yTFsW(){return Q2;}())](RlRxO[Cmkjm(NbKfW) + gHND +" ascii
    $s11 = "tion e(){return SvHY;}())](SDSYE, 0, 0);};function WJNV(){return poqR(ZXuhT) + (function op(){return vHTA;}()) + (function WKPe(" ascii
    $s12 = "](Os + QCsSA(IwxZL) + LCf(jVP) + (function bKuA(){return gMbVE;}()) + (function uW(){return IXJxv;}()));SbxAw[((function l(){ret" ascii
    $s13 = "ue; while (V){try {RlRxO[SLL(GKj) + oiC(NHphL)](L0(CX), (function T(){return oc;}()) + SYL + chpCS(Wcp) + (function p(){return n" ascii
    $s14 = " ZWP(yr)]);SbxAw[Wd(Dj) + (function RbDC(){return XX;}()) + p0] = 0;SbxAw[U + Gq(w) + JHZK(n) + P](VEcbA, 2 );SbxAw[DutkG + K(xB" ascii
    $s15 = "bg) + S](MvNa(Zj) + Dl(NX) + (function mHv(){return Yk;}()) + (function dNZgt(){return hF;}()));}();function RbtL(SDSYE){Q[(func" ascii
    $s16 = "xcv(Fw) + (function fy(){return JL;}()) + fJAq, false);RlRxO[pElD(id) + (function GVwHu(){return Tv;}())]();while (RlRxO[(functi" ascii
    $s17 = "ion wAsC(){return AQGmj;}()) + scEB(hdE) + aSo(Fwjiq) + tGv(Qkz) + (function N(){return ZA;}()) + VyOE(m) + (function gNqzb(){re" ascii
    $s18 = "ajksu(y0)](C());var V0 = new this[cHOZY + FzikT(mzv)]();var Q1 = V0[(function pR(){return DswF;}()) + f(y) + e0(DUyii) + (functi" ascii
    $s19 = "turn OeU;}())]((function vR(){return erq;}()) + (function y1(){return fK;}()) + (function VKkHf(){return skR;}())) + C0(JV) + (f" ascii
    $s20 = "T;}()) + (function eMK(){return SzZjV;}()) + L1 + (function PQ(){return LgAUV;}()) + BiK + (function PBgI(){return Fmo;}()) + FI" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}