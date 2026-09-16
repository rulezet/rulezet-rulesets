rule sig_20160318_188d8657f79d129c5e57c944d2016120 {
  meta:
    description = "datamaliciousorder - file 20160318_188d8657f79d129c5e57c944d2016120.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7602d1dc64052fa4c377421b683e2f83f72e10df75edf9d1912df0cde59343f3"

  strings:
    $s1  = "var XuhW = \"\\x69n\\x21\";var zlK = \"y a\\x67a\";var Gw = \"\\x2c \\x74\\x72\";var bC = \"e\";var mmK = \"Ple\\x61s\";var yRbV" ascii
    $s2  = "harAt\"](4);var TXf = \"bje\\x63\";var x = \"a\\x74\\x65O\";var F = \"\\x43r\\x65\";var X = function BO() {return WScript[(funct" ascii
    $s3  = "ction nP(){return Qa;}())](j() * 10)};wnzO = WScript[xAfp()]((function Sl(){return HDIhX;}()) + (function pVsE(){return EynR;}()" ascii
    $s4  = " y;}()) + (function Sesb(){return QuuLh;}()) + (UeipN) + (ElBPQ)] < 4 ) {WScript[(mFKpW) + (function jM(){return KKL;}()) + (fun" ascii
    $s5  = "}()); rmb = rtl(); p = WScript[(F) + (function SFEN(){return x;}()) + (function sATzI(){return TXf;}()) + (function BFvR(){retur" ascii
    $s6  = "yDOy;}()) + (bH) + (jQp) + (B) + (function N(){return ARQ;}())]();WScript[(mFKpW) + (KKL) + (function q0(){return Qa;}())](j());" ascii
    $s7  = "){return jQp;}()) + (function RHvAh(){return B;}()) + (function sxoH(){return ARQ;}())]();WScript[(function czlz(){return mFKpW;" ascii
    $s8  = "eturn cdftx;}()) + (yRbV);}else{WScript.Echo((mmK) + (function ssNyb(){return bC;}()) + (function t(){return Gw;}()) + (zlK) + (" ascii
    $s9  = " (function aa(){return Xcoz;}()) + (function ygF(){return G;}());};function QFkJ(rynJ, lOTVn){return rynJ - lOTVn;};function xAf" ascii
    $s10 = "nction uX() {return jS && rYK;};if (uX()){vsc = X[(r) + (function SsZMG(){return tiVkR;}()) + (function a(){return gBQZb;}()) + " ascii
    $s11 = "j;}())]();var ny = Iy[(function S(){return QyDOy;}()) + (function cXnAb(){return bH;}()) + (jQp) + (function OaMUD(){return B;}(" ascii
    $s12 = "var Iy = new this[(function buxWA(){return o;}()) + (Zj)]();var n = Iy[(function Sn(){return QyDOy;}()) + (bH) + (function BLRE(" ascii
    $s13 = "n q;}())](rmb);p[(function g(){return C0;}())]((Lw), (function qCpqQ(){return ZjoZ;}()) + (function w(){return DH;}()) + (xwmsb)" ascii
    $s14 = "eturn F;}()) + (x) + (function DF(){return TXf;}()) + (function nPNjC(){return q;}())]((function vY(){return ocX;}()) + (functio" ascii
    $s15 = ")) + (S1) + (WZ), false);p[(function Czb(){return oaCm;}()) + (function glm(){return QZVMC;}())]();while (p[(function M(){return" ascii
    $s16 = "eturn LVzTa;}())) + (function nc(){return b0;}()) + (function pEUfl(){return FcE;}()) + (function Mwwi(){return xIHu;}()) + (fun" ascii
    $s17 = "S ? (GWJr) + (function ML(){return bl;}()) + (function QH(){return iO;}()) : (function ONy(){return l;}()) + (function MKtJZ(){r" ascii
    $s18 = "0, 0);};function rtl(){return (function kE(){return C;}()) + (function cCZm(){return LG;}()) + (function L(){return scwfN;}()) +" ascii
    $s19 = "p(){return (F) + (function IapK(){return x;}()) + (function bTYgz(){return TXf;}()) + (function eDQBk(){return q;}());};function" ascii
    $s20 = ")) + (function vc(){return ARQ;}())]();var xPQcR = \"btT\";xPQcR = QFkJ(n, GKFVK);var HwkZ = \"tI\";HwkZ = QFkJ(ny, n);return QF" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}