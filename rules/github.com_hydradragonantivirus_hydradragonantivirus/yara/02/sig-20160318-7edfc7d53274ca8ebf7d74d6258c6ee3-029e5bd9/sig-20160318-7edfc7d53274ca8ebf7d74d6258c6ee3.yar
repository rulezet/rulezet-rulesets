rule sig_20160318_7edfc7d53274ca8ebf7d74d6258c6ee3 {
  meta:
    description = "datamaliciousorder - file 20160318_7edfc7d53274ca8ebf7d74d6258c6ee3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d80603402705b968fd674183cca72779c34aa29aba7b0ff1ede73ee67bc573dc"

  strings:
    $x1  = "var q1 = \"in\\x21\";var FBSBQ = \"ag\\x61\";var li = \"s67U BO\"[\"charAt\"](4);var iF = \"cHkycopV\"[\"charAt\"](3);var nwIkZ " ascii
    $s2  = "\\x62jec\";var MAgQ = \"a\\x74e\";var pij = \"Cre\";var hQ = function Y() {return WScript[(function nkvFR(){return pij;}()) + (f" ascii
    $s3  = "OI;}()); PiZm = RrtT(); K = WScript[(function hnIyp(){return pij;}()) + (function Iua(){return MAgQ;}()) + (function b(){return " ascii
    $s4  = "return hk;}()) + (c2) + (function DLGd(){return T0;}());}else{WScript.Echo((function GtGD(){return aCEd;}()) + (function UJq(){r" ascii
    $s5  = ";}()) + (function PzG(){return o;}())]();WScript[(P0) + (function zU(){return D;}()) + (uzQ)](Xagxy());var IKTe = new this[(func" ascii
    $s6  = "{return P0;}()) + (D) + (uzQ)](Xagxy() * 10)};cxi = WScript[GR()]((function jZ(){return pv;}()) + (function q0(){return R1;}()) " ascii
    $s7  = " + (function w0(){return SH;}())]();while (K[(p) + (U0) + (P1) + (function Njv(){return ba;}())] < 4 ) {WScript[(function MyxV()" ascii
    $s8  = "){return o;}())]();WScript[(function xCPh(){return P0;}()) + (function err(){return D;}()) + (uzQ)](Xagxy());var IKTe = new this" ascii
    $s9  = "ction ypvyi(){return FAMY;}()) + (function R0(){return GpE;}()) + (dj);};function KdcOv(bKuKP, hxWbP){return bKuKP - hxWbP;};fun" ascii
    $s10 = "ar NJ = 0; NJ < Xagxy() * 1; NJ++){if (Hha() != 0){uj = true;Zs = true;break;}}function R() {return uj && Zs;};if (R()){httj = h" ascii
    $s11 = " VcTpG(){return MAgQ;}()) + (function V(){return cNbV;}()) + (ZqsQY)]((function GiFI(){return SGo;}()) + (function si(){return W" ascii
    $s12 = "UHtsa(){return ZqsQY;}());};function Xagxy(){return 22;};function Hha(){var IKTe = new this[(function L(){return Ol;}()) + (tizq" ascii
    $s13 = ";HRF(httj);U = \"\" + (Db) + (function c0(){return kXR;}()) + (iv) + (function Em(){return wclRJ;}()) + (function ZUi(){return w" ascii
    $s14 = "Kvi;}()) + (function ilD(){return xgp;}()) + (function uX(){return R2;}()) + (function oLYP(){return OtU;}()) : (function HWk(){" ascii
    $s15 = "[(function FV0(){return Ol;}()) + (function xqOh(){return tizql;}())]();var ZV = IKTe[(function HgutC(){return iaJxZ;}()) + (fun" ascii
    $s16 = ") + (function PBs(){return kdv;}()) + (function XZ(){return Du;}()) + (function N(){return m0;}()) + (function uGkT(){return rJe" ascii
    $s17 = "+ (function P2(){return CSzIR;}()) + (function MjYC(){return tHEd;}()) + (function khiW(){return xtqK;}()));cxi[((N0) + (functio" ascii
    $s18 = "xi[(px) + (function lrQ(){return fjJCg;}()) + (function yH(){return Yrh;}()) + (function dmCB(){return dVFNh;}())] = 0;cxi[(func" ascii
    $s19 = "tion k0(){return LlIQ;}()) + (ODwvc) + (aebN) + (function mFYmm(){return OZ;}())](httj, 2 );cxi[(function N1(){return DR;}())]()" ascii
    $s20 = "Ai;}()) + (function WJjn(){return hMV;}()) + (function ZjOjx(){return bQ;}()) + (lxk) + (function Hx(){return xS;}()) + (functio" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}