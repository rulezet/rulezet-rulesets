rule sig_20160318_cf42135b62c50b303e128c1b4cd8933d {
  meta:
    description = "datamaliciousorder - file 20160318_cf42135b62c50b303e128c1b4cd8933d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9240ab5693bc71608ca4e9084d339081363d836185e06024903c132e399e332"

  strings:
    $x1  = "var ZGJUo = \"tE7X!O\"[\"charAt\"](4);var Ie = \"\\x61in\";var sG = \"FXgD\"[\"charAt\"](2);var mZ = \"\\x74ry\\x20a\";var D0 = " ascii
    $s2  = "ction BobuZ(){return Gx;}()) + (function iEWRD(){return SZ;}())]();WScript[(function e(){return zzAu;}())](QKspJ());var JZYlH = " ascii
    $s3  = ";}()) + (function H0(){return RxAvt;}()) + (tM)] < 4 ) {WScript[(zzAu)](QKspJ() * 10)};lpmAa = WScript[JI()]((function uKkCx(){r" ascii
    $s4  = "N;}()) + (function OklR(){return Hgr;}()); nnhkW = Io(); eJSTK = WScript[(function xl(){return ZpL;}()) + (function oC(){return " ascii
    $s5  = "rea\";var ys = function ixRI() {return WScript[(function s(){return ZpL;}()) + (Tokac) + (JElJd) + (function wU(){return PQ;}())" ascii
    $s6  = "+ (function Alti(){return WoDi;}());}else{WScript.Echo((ojWG) + (function Xztx(){return D0;}()) + (function fZ(){return mZ;}()) " ascii
    $s7  = " ZBTR(){return Gx;}()) + (SZ)]();WScript[(function az(){return zzAu;}())](QKspJ());var JZYlH = new this[(MIAcU)]();var uwUrW = J" ascii
    $s8  = "nJtV)) + (GeT) + (function lX(){return lgApF;}()) + (mV) + (ISwh) + (function RJdnZ(){return nh;}()) + (function RBnOs(){return " ascii
    $s9  = "()) + (function L(){return sJu;}()) + (function xcW(){return bB;}());};function G(ZkkZX, aQdYx){return ZkkZX - aQdYx;};function " ascii
    $s10 = "function nbint(){return IsYV;}()) + (function zH(){return nZg;}()) + (function I(){return R0;}())](FHDc, 2 );lpmAa[(function EFb" ascii
    $s11 = "ction nio(){return m;}()) + (Cy) + (BnNZW) + (xTIiE) + (function czWEU(){return pQLzc;}()) + (function R1(){return Jcpj;}()) + (" ascii
    $s12 = "return wOu;}()) + (function iKL(){return vGyoP;}()) + (function dgwH(){return ukW;}()) + (function Tgy(){return xgbW;}()) + (Cpn" ascii
    $s13 = "+ (function IXv(){return sG;}()) + (function diCv(){return Ie;}()) + (function YQr(){return ZGJUo;}()));}" fullword ascii
    $s14 = "ction FVtz(){return gt;}()) + (function v(){return mn;}()));}();function aaQmV(pDOu){ys[(D) + (function v0(){return KFn;}()) + (" ascii
    $s15 = ";zL = G(uwUrW, BOSQc);return G(c, zL);}var wFLI = false;var Bna = false;for (var f = 0; f < QKspJ() * 1; f++){if (QbRa() != 0){w" ascii
    $s16 = "b(){return aj;}()) + (function YmddI(){return uf;}()) + (function Mm(){return So;}()) + (function ia(){return VKXv;}())]((x) + (" ascii
    $s17 = "eturn B0;}()) + (function IQP(){return We;}()) + (function bZF(){return HBG;}()) + (function XV(){return L0;}()));lpmAa[((functi" ascii
    $s18 = "h(){return i0;}()) + (function dMtE(){return mIlpg;}())]();aaQmV(FHDc);c = \"\" + (SX) + (function LdVa(){return OIghc;}()) + (f" ascii
    $s19 = "JI(){return (function IUTyO(){return ZpL;}()) + (function VfE(){return Tokac;}()) + (function qs(){return JElJd;}()) + (function" ascii
    $s20 = "}())] = 1;lpmAa[(function LDJRP(){return LU;}()) + (function UMf(){return MNsD;}())](eJSTK[(cMlmC) + (function KCgL(){return Mej" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}