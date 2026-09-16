rule sig_20160321_19dd9f7ff6c52356c3d8decb05dbe8e8 {
  meta:
    description = "datamaliciousorder - file 20160321_19dd9f7ff6c52356c3d8decb05dbe8e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efe0ee355bdd9404bbc1520d929dc76fe69a4e285b8f604d42b4d8d4cbc5ec60"

  strings:
    $s1  = "function cuV(LKlRH){return LKlRH;};function wlDOd(iIlnT){return iIlnT;};var on = \"\\x38162\";var r0 = \"\\x33\\x36\";var Popa =" ascii
    $s2  = "xOkW(){return p0;}()) + xP(SmR) + QxCTW(siZ) + (function v(){return UyLxG;}()); XNXU = s(); V = WScript[ZtaR(iXC) + (function MG" ascii
    $s3  = "ile (V[(function nlVWQ(){return Bf;}()) + xuvZC(hD) + LqYY(aAu)] < 4 ) {WScript[(function If(){return ba;}()) + (function LLyj()" ascii
    $s4  = "s0 = function h() {return WScript[(function EqEO(){return iXC;}()) + (function Qk(){return Zvj;}()) + (function WZVim(){return R" ascii
    $s5  = "){return eTxj;}()) + q(WqxiC)]();WScript[(function KwaQO(){return ba;}()) + (function zh(){return e;}())](ZP());var Y = new this" ascii
    $s6  = " P(thS) + fFA(GhSvm) + wJ(eTxj) + (function Yx(){return WqxiC;}())]();WScript[(function ReK(){return ba;}()) + (function mJTEJ()" ascii
    $s7  = "/\";var vS = \"http\";var Zvou = \"GET\";function Gdqo(parU){return parU;};var oIYVc = \"open\";var QAwz = \"h8b6b\";var mYtce =" ascii
    $s8  = " + AHw(hzUZ) + yaT;};function GLJm(uuOYy, JNCS){return uuOYy - JNCS;};function fl(){return UIzb(iXC) + Piv(Zvj) + Rq + Pa(OT) + " ascii
    $s9  = "eak;}}function bqj() {return lwtM && YBiJY;};if (bqj()){Q = s0[(function fymWh(){return Mhd;}()) + y + tGyA + oxhK(kkUBy) + Im +" ascii
    $s10 = "{return e;}())](ZP() * 10)};AbrdC = false;} catch(e){};}SQHP = WScript[fl()]((function iFkq(){return z1;}()) + (function Ybb(){r" ascii
    $s11 = "\";var RJu = O0[\"\\x63h\\x61rAt\"](3);var lGjar = \"g\\x65t\";var dj = \"D\\x61\\x74e\";var e = \"ep\";var ba = \"S\\x6ce\";fun" ascii
    $s12 = "var NDl = \"\\x6ae\";var Z = QAwz[\"\\x63h\\x61rAt\"](2);var DGJfS = \"ateO\";var X = \"C\\x72e\";function xP(vNEC){return vNEC;" ascii
    $s13 = "gJdh;};function BD(SAGu){return SAGu;};function H(FUe){return FUe;};var A = \"IEJh\";var LRDSQ = \"ell\";var S = A[\"\\x63h\\x61" ascii
    $s14 = "[\"\\x63h\\x61rAt\"](3);var G0 = Q1[\"\\x63h\\x61rAt\"](0);var XzDi = \"Creat\";function AHw(CTU){return CTU;};var yaT = \"P\";v" ascii
    $s15 = "xCTW(dyvb){return dyvb;};var oK = \"XQ7B5eB0WnO\";var UyLxG = \"xe\";var siZ = oK[\"\\x63h\\x61rAt\"](5);var SmR = \"\\x6eC5Q.\"" ascii
    $s16 = "eturn XrM;}()) + l + jGLq);SQHP[((function z0(){return oIYVc;}()))]();SQHP[NQ(suik) + hc(XBrH)] = 1;SQHP[SYPA + P0(N0)](V[BNWRg(" ascii
    $s17 = "m(AT, Kgi);}var lwtM = false;var YBiJY = false;for (var cY = 0; cY < ZP() * 1; cY++){if (ABr() != 0){lwtM = true;YBiJY = true;br" ascii
    $s18 = " (function GkANS(){return R0;}())](mMNX + (function BYPw(){return hTy;}())) + AqM + (function RoSJ(){return nV;}()) + (function " ascii
    $s19 = "v(nluu) + m0(LElcg) + lwtM ? v0(Dm) + hZ(lnTB) + mBBX(Xy) : (function OzFxt(){return xtjBu;}()) + cuV(Popa) + (function jH(){ret" ascii
    $s20 = "ction s(){return (function ASwQ(){return UZR;}()) + (function IZNM(){return bDKgf;}()) + MOzCh + (function mqSw(){return vp;}())" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}