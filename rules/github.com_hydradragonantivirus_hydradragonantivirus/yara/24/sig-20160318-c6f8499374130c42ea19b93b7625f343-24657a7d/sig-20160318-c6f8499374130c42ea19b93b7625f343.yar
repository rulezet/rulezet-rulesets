rule sig_20160318_c6f8499374130c42ea19b93b7625f343 {
  meta:
    description = "datamaliciousorder - file 20160318_c6f8499374130c42ea19b93b7625f343.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6af64bb47563fc497029e16c6065c3b554b64ecc982c5414d40eeb8ec3438f1"

  strings:
    $s1  = "var GcI = \"!\";var rZ = \"gain\";var J1 = \"y\\x20a\";var K0 = \"\\x20t\\x72\";var cswVV = \"WrF,X3c\"[\"charAt\"](3);var TN = " ascii
    $s2  = "turn lwcSs;}()) + (function SXkoo(){return Y0;}())] < 4 ) {WScript[(Y)](PFd() * 10)};Z0 = WScript[xePn()]((function nsQB(){retur" ascii
    $s3  = "n Nm;}());}else{WScript.Echo((function yEhXC(){return QT;}()) + (function uvxj(){return gHW;}()) + (function adMrO(){return m0;}" ascii
    $s4  = "= \"r\";var xRc = \"\\x43\";var z = function J() {return WScript[(function nU(){return xRc;}()) + (function Rzs(){return bBCb;}(" ascii
    $s5  = "kLR;}()) + (function E(){return uiuX;}()) + (Hhf) + (q) + (function Q(){return cJz;}())]();WScript[(function oXU(){return Y;}())" ascii
    $s6  = "rn N;}()) + (function BYl(){return Si;}()) + (function GSpm(){return hrPLM;}()); SUA = aGi(); wxi = WScript[(function o(){return" ascii
    $s7  = "eturn u - BnZ;};function xePn(){return (xRc) + (function jOTg(){return bBCb;}()) + (function YTg(){return s;}()) + (function nw(" ascii
    $s8  = " < PFd() * 1; n++){if (j() != 0){Wri = true;thRj = true;break;}}function Z() {return Wri && thRj;};if (Z()){ZdK = z[(UYd) + (mc)" ascii
    $s9  = "return cJz;}())]();WScript[(function pPtP(){return Y;}())](PFd());var oB = new this[(qB)]();var tZ = oB[(function vRj(){return g" ascii
    $s10 = "()) + (function iru(){return TN;}()) + (function Czyu(){return cswVV;}()) + (K0) + (function eAYj(){return J1;}()) + (function M" ascii
    $s11 = "(PUmL){z[(function ybQow(){return mMh;}())](PUmL, 0, 0);};function aGi(){return (function lKoel(){return TQXxN;}()) + (function " ascii
    $s12 = "(function x(){return drqJ;}()) + (flLEg)]((function QQ(){return jMA;}()), (function OF(){return EPw;}()) + (function yDVfg(){ret" ascii
    $s13 = " xRc;}()) + (function OhfTm(){return bBCb;}()) + (function sErS(){return s;}()) + (function hAs(){return M;}()) + (p)](SUA);wxi[" ascii
    $s14 = "urn qB;}())]();var ZU = oB[(function ENshm(){return gkLR;}()) + (uiuX) + (function dy(){return Hhf;}()) + (q) + (function TuL(){" ascii
    $s15 = " + (function pDo(){return V;}()) + (function mMezP(){return virHl;}()) + (function b(){return TcSQ;}()) + (function rIMjm(){retu" ascii
    $s16 = "(function N0(){return aa;}()) + (function j1(){return E0;}()) + (function ic(){return aVIXW;}()) + (function I0(){return c0;}())" ascii
    $s17 = "urn YpJ;}()) + (oKML) + (function rSd(){return Bc;}()) + (function T(){return DrSLM;}()) + (function tRrj(){return awRq;}()) + (" ascii
    $s18 = "unction b1(){return n0;}())] = 0;Z0[(function dr(){return VxwEQ;}()) + (function WxHd(){return t;}()) + (ZljE)](ZdK, 2 );Z0[(IMy" ascii
    $s19 = "urn tOF;}()), false);wxi[(gnNGo)]();while (wxi[(function lO(){return VF;}()) + (function oX(){return nV;}()) + (function Y1(){re" ascii
    $s20 = "){return M;}()) + (function J0(){return p;}());};function PFd(){return 22;};function j(){var oB = new this[(function YVSwB(){ret" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}