rule sig_20160318_7f2ab422cb5c0a89e8817d2e2bc8ec8d {
  meta:
    description = "datamaliciousorder - file 20160318_7f2ab422cb5c0a89e8817d2e2bc8ec8d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ddbb06ecab8a251c6e395acb9377dd949ea6f23486944d90ba770661858e9cf"

  strings:
    $s1  = "var lLvsD = \"\\x6e!\";var L = \"ai\";var CfvX = \"y a\\x67\";var Opa = \"r\";var pTEXY = \"\\x2c \\x74\";var ECK = \"se\";var p" ascii
    $s2  = "2j\";var UrW = \"rea\";var TjuuH = \"9ZgvC52\"[\"charAt\"](4);var joR = function odfcO() {return WScript[(function KVxvR(){retur" ascii
    $s3  = "eturn jWASc;}()); mDg = tg(); I = WScript[(function zhtGq(){return TjuuH;}()) + (UrW) + (UopO) + (function UG(){return Rbrc;}())" ascii
    $s4  = " 4 ) {WScript[(function nFS(){return jHx;}()) + (B)](kD() * 10)};nwYpC = WScript[DM()]((function uFK(){return I0;}()) + (OpIhh) " ascii
    $s5  = "VF;}()) + (kyC) + (function yMkX(){return zU;}())]();WScript[(jHx) + (function mV(){return B;}())](kD());var wn = new this[(Tg)]" ascii
    $s6  = "b(){return SOjVF;}()) + (function OO(){return kyC;}()) + (function FsbB(){return zU;}())]();WScript[(jHx) + (function AUHee(){re" ascii
    $s7  = "return gnrO;}());}else{WScript.Echo((n) + (function DO(){return pCl;}()) + (function KUj(){return ECK;}()) + (function GYAk(){re" ascii
    $s8  = "nction gLUhd(){return Ll;}()) + (function ti(){return xxV;}());};function g(g0, aTsAP){return g0 - aTsAP;};function DM(){return " ascii
    $s9  = "lse;for (var K = 0; K < kD() * 1; K++){if (Ftaju() != 0){iEg = true;JOVT = true;break;}}function qz() {return iEg && JOVT;};if (" ascii
    $s10 = "l2oz\"[\"charAt\"](2);var BuSS = \"cmbaT\"[\"charAt\"](3);var y0 = \"Kf4\"[\"charAt\"](1);var A = \"uh\\x69s\\x64\";var MmLRw = " ascii
    $s11 = ";}()) + (function hz(){return UrW;}()) + (function xBWa(){return UopO;}()) + (function V(){return Rbrc;}()) + (hopZ)]((duk) + (f" ascii
    $s12 = "+ (function g1(){return f;}())]((function DyPuV(){return x;}()) + (function UX(){return nzb;}())) + (function U(){return O;}()) " ascii
    $s13 = " Nj(){return BuSS;}()) + (function DCZJS(){return NZq;}()) + (MlSOH) + (function cVk(){return z;}()) : (oYPys) + (function vR(){" ascii
    $s14 = "turn pTEXY;}()) + (function ZLIBA(){return Opa;}()) + (function bae(){return CfvX;}()) + (function D(){return L;}()) + (function" ascii
    $s15 = "unction a(){return EyCze;}()) + (function oLNq(){return P;}()) + (oZkG) + (function pGT(){return E;}()) + (Xcm));}();function nW" ascii
    $s16 = "n oTkP(){return YF;}())] = 0;nwYpC[(function j(){return hoQ;}()) + (function Gdx(){return xSKM;}()) + (function LN(){return nxz;" ascii
    $s17 = ")) + (function H0(){return wLX;}()) + (function TDQy(){return MmLRw;}()) + (A) + (function kA(){return y0;}()) + iEg ? (function" ascii
    $s18 = " (function GEs(){return dmJku;}()) + (function Iu(){return xsY;}()) + (EzzMe)]);nwYpC[(function YHvP(){return QH;}()) + (functio" ascii
    $s19 = "}()) + (function WpKk(){return peCKL;}())](SjX, 2 );nwYpC[(function vLfrb(){return omFLF;}()) + (function P1(){return DW;}())]()" ascii
    $s20 = "();var OeVQ = wn[(function R(){return aOwQ;}()) + (function qst(){return l;}()) + (function Qx(){return jTTY;}()) + (function SF" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}