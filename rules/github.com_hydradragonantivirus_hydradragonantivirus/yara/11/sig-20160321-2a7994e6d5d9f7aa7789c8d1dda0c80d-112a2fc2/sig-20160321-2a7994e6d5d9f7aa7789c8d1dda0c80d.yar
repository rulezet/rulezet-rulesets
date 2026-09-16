rule sig_20160321_2a7994e6d5d9f7aa7789c8d1dda0c80d {
  meta:
    description = "datamaliciousorder - file 20160321_2a7994e6d5d9f7aa7789c8d1dda0c80d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13787c06e58d6add5c39699bb17f7d6a8c38a20b3a010d070a6e1c06f3c437e5"

  strings:
    $s1  = "function T(NYBw){return NYBw;};var HsKa = \"68162\";var Bt = \"2\\x318\\x33\";var Kk = \"\\x66\";var Hjma = \"sd\";var xVR = \"d" ascii
    $s2  = "0(){return BCmDv;}()) + t + (function Cj(){return P;}()) + VmDQA(N) + xr + X1(HQIvn) + kmyTK(v)]();WScript[jdAR(Ziu)](bX());var " ascii
    $s3  = "\\x74\"](1);var a = UEo[\"ch\\x61\\x72A\\x74\"](5);var hrZQ = function ZWdIj() {return WScript[(function xzu(){return a;}()) + (" ascii
    $s4  = ";}()) + (function oIn(){return pkM;}()) + (function TlzkF(){return O0;}()); sjOvV = zgo(); Zk = WScript[(function R(){return a;}" ascii
    $s5  = "){return P;}()) + (function S(){return N;}()) + (function B(){return xr;}()) + (function OQ(){return HQIvn;}()) + v]();WScript[h" ascii
    $s6  = "ction ET(Xn, oKy){return Xn - oKy;};function nst(){return (function iN(){return a;}()) + rfOcF + i(X) + bLXGf + xv(K) + wWz(RgoF" ascii
    $s7  = "jWBz = new this[(function L(){return cN;}()) + sz]();var YHi = jWBz[(function uWGxR(){return BCmDv;}()) + bUxEQ(t) + Tdbz(P) + (" ascii
    $s8  = "= \"\\x44gi\";var zcI = \"4\\x4bx\";function thP(KGEp){return KGEp;};var l0 = \"%/\";var y0 = \"%TEMP\";function YZY(CPXP){retur" ascii
    $s9  = " y < bX() * 1; y++){if (F() != 0){LMNLq = true;RPDaM = true;break;}}function z() {return LMNLq && RPDaM;};if (z()){Oi = hrZQ[YZY" ascii
    $s10 = "j);};function bX(){return 22;};function F(){var jWBz = new this[cN + sz]();var Ets = jWBz[tiaPK(BCmDv) + fAw(t) + (function jJC(" ascii
    $s11 = "]();while (Zk[h(jwJoP) + D0(ajze)] < 4 ) {WScript[RE(Ziu)](bX() * 10)};MomVF = false;} catch(e){};}eO = WScript[nst()]((function" ascii
    $s12 = "t) + (function xyxx(){return CoP;}()) + (function fxURD(){return UQOO;}()) + crbw + (function mKPoX(){return g0;}()) + LMNLq ? e" ascii
    $s13 = "n ROubQ(){return rfOcF;}()) + (function X0(){return X;}()) + wYUpQ(bLXGf) + kgknd(K) + (function xfQ(){return RgoFj;}())](QtpM(c" ascii
    $s14 = "unction zgo(){return sAmw + (function G(){return k;}()) + (function ioC(){return Z;}()) + (function n0(){return EIVUE;}());};fun" ascii
    $s15 = "function j0(){return N;}()) + AAL(xr) + (function RwVK(){return HQIvn;}()) + (function i0(){return v;}())]();var n = \"Gos\";n =" ascii
    $s16 = "tion Sm(){return mLT;}()) + (function lL(){return t2;}())](Zk[cnwhq(yDjn) + (function I(){return qsZSa;}()) + VWaYE(flw) + (func" ascii
    $s17 = " thXI(LcdoM)](thP(y0) + (function u0(){return l0;}())) + zcI + t1 + (function e0(){return gfC;}()) + (function zPL(){return uMID" ascii
    $s18 = "UXr) + (function lMD(){return plUgc;}()) + (function Qz(){return JR;}()));}();function tebRr(GlVgY){hrZQ[PyqZm](GlVgY, 0, 0);};f" ascii
    $s19 = "ybsy(Ziu)](bX());var jWBz = new this[(function O(){return cN;}()) + (function p(){return sz;}())]();var rJulK = jWBz[(function k" ascii
    $s20 = "(gUPCj) + (function mA(){return zEL;}()) + iDuc(ydiw) + (function SECbc(){return jfWKt;}()) + UCTr(NED) + fszR(kavNP) + L0(p0) +" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}