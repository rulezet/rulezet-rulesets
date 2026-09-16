rule sig_20160318_38abb809815380135bfbf58cf8b7a092 {
  meta:
    description = "datamaliciousorder - file 20160318_38abb809815380135bfbf58cf8b7a092.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f03e61c6a35f9fa7159ce5f9b990c138307fbd38c28bbd9628c6fb835534fdf"

  strings:
    $s1  = "var kzZQ = \"CVf5L!n\"[\"charAt\"](5);var eAR = \"\\x67ai\\x6e\";var dGt = \"y a\";var T0 = \"\\x2c\\x20tr\";var Y1 = \"se\";var" ascii
    $s2  = "eturn zGj;}()) + (function QD(){return Jfbi;}())](BacBe() * 10)};YywxS = WScript[YyzK()]((function wHTM(){return B0;}()) + (func" ascii
    $s3  = "();WScript[(function Oe(){return zGj;}()) + (function GQYj(){return Jfbi;}())](BacBe());var vqaa = new this[(jV)]();var pZE = vq" ascii
    $s4  = "var wD = vqaa[(function r(){return TH;}()) + (function dY(){return qs;}()) + (E0) + (W)]();WScript[(function Txd(){return zGj;}(" ascii
    $s5  = "T)]();while (AaVBY[(function yui(){return QOlgn;}()) + (v) + (function oJK(){return DiziD;}())] < 4 ) {WScript[(function Brw(){r" ascii
    $s6  = "){return UVxoo;}());}else{WScript.Echo((function L(){return Jkcx;}()) + (function Xk0(){return dDwGN;}()) + (function R(){return" ascii
    $s7  = "return eBBO - BFaQy;};function YyzK(){return (function DOjvQ(){return GsuRP;}()) + (function ZYeH(){return bb;}()) + (function p" ascii
    $s8  = "= 0; nA < BacBe() * 1; nA++){if (qFYM() != 0){I = true;IjSUb = true;break;}}function yH() {return I && IjSUb;};if (yH()){nqap = " ascii
    $s9  = " \"\\x65ct\";var zIH = \"t\\x65\\x4fb\\x6a\";var bb = \"\\x72ea\";var GsuRP = \"C\";var GS = function jdduU() {return WScript[(f" ascii
    $s10 = "eturn GGB;}()) + (function jv(){return d1;}()); JBCam = lszJ(); AaVBY = WScript[(GsuRP) + (function iDa(){return bb;}()) + (func" ascii
    $s11 = "ion oT(){return u1;}()) + (function kdW(){return dJM;}())] = 0;YywxS[(GSkw) + (function o(){return wTAD;}()) + (Xz)](nqap, 2 );Y" ascii
    $s12 = "urn YjZU;}())]((function X(){return d2;}()) + (function HbK(){return Y;}()) + (function M(){return O;}()), (IFi) + (y) + (functi" ascii
    $s13 = " (function S(){return mFsO;}()) + (zWNsi) + (function LWWtK(){return u0;}()) + (function apqLw(){return i;}()) + (function h(){r" ascii
    $s14 = "H;}()) + (function EKoT(){return SXRD;}()) + (function LfLQ(){return H;}()) + (function bf(){return uzj;}()) + (function p(){ret" ascii
    $s15 = "aa[(TH) + (function k(){return qs;}()) + (function Xk(){return E0;}()) + (function dkqEF(){return W;}())]();var mEE = \"wMj\";mE" ascii
    $s16 = "LWWh;}()) + (function B(){return bQ;}()) + (function l(){return JAaqj;}()) + (function kYDn(){return ACYY;}()), false);AaVBY[(ms" ascii
    $s17 = "O;}()) + (mQAnD)](AaVBY[(function iNW(){return QYYiD;}()) + (Mq) + (Tu)]);YywxS[(function HkI(){return VE;}()) + (JZJC) + (funct" ascii
    $s18 = "Q(){return zIH;}()) + (U);};function BacBe(){return 22;};function qFYM(){var vqaa = new this[(function bogP(){return jV;}())]();" ascii
    $s19 = "{return GsuRP;}()) + (function oM(){return bb;}()) + (function WWV(){return zIH;}()) + (function hfAF(){return U;}())]((function" ascii
    $s20 = "on WfG(){return Od;}()) + (NunL) + (function NRanI(){return xC;}()) + (function NADyg(){return P;}()) + (function iea(){return k" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}