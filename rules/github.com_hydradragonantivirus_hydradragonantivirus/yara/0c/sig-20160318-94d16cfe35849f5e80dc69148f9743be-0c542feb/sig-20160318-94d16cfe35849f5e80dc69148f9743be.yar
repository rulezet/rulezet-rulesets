rule sig_20160318_94d16cfe35849f5e80dc69148f9743be {
  meta:
    description = "datamaliciousorder - file 20160318_94d16cfe35849f5e80dc69148f9743be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6defa87a75255ff7e67210c2e3e062479354bf830885f79a716968efdbbb7595"

  strings:
    $x1  = "var i2 = \"\\x6e!\";var O0 = \"a\\x67ai\";var L0 = \"\\x20try \";var t1 = \"as\\x65,\";var TP = \"feF\"[\"charAt\"](1);var bUL =" ascii
    $s2  = " = \"C\\x72\\x65a\";var ks = function CpWXS() {return WScript[(function eBra(){return QUJPl;}()) + (u) + (function lqwxI(){retur" ascii
    $s3  = "{return i;}()) + (function V(){return VNE;}()) + (function rqqVH(){return wIr;}()) + (function B(){return FWRsm;}())]();WScript[" ascii
    $s4  = "unction SrF(){return y1;}()) + (function Av(){return OU;}());}else{WScript.Echo((bUL) + (TP) + (t1) + (L0) + (O0) + (function Hj" ascii
    $s5  = ")) + (function UEERx(){return wIr;}()) + (function xk(){return FWRsm;}())]();WScript[(function pS(){return ORTWS;}()) + (functio" ascii
    $s6  = "WScript[(function Hq(){return ORTWS;}()) + (function Fr(){return teKb;}())](ry() * 10)};Mu = WScript[tG()]((function JjsW(){retu" ascii
    $s7  = " lj;}()) + (function i0(){return eSco;}()); J = I(); mHDb = WScript[(function wUkn(){return QUJPl;}()) + (u) + (function NaG(){r" ascii
    $s8  = "}function ZgLU() {return jOK && glYRe;};if (ZgLU()){Gu = ks[(Th) + (function tAp(){return Xnht;}()) + (DRE) + (function ZpwnY(){" ascii
    $s9  = " (function ZYpkK(){return CoPE;}()) + (function eijwe(){return Hi;}()) + (function zPmL(){return m;}()) + (function rJGsJ(){retu" ascii
    $s10 = "A(){return S;}()) + (function Br(){return y0;}()) + (function xKQ(){return wSFF;}()) + (function Wie(){return KVTg;}())] < 4 ) {" ascii
    $s11 = " sjf;}()) + jOK ? (t0) + (function v(){return S0;}()) + (function kAAvr(){return THlXJ;}()) : (function B1(){return fe;}()) + (f" ascii
    $s12 = ";}();function k(gf){ks[(function fmX(){return hlVmy;}())](gf, 0, 0);};function I(){return (function Bt(){return iy;}()) + (funct" ascii
    $s13 = "{return xd;}()) + (bIyJ)) + (function hPUcU(){return LoEQ;}()) + (O) + (function Vp(){return sSzhu;}()) + (function idi(){return" ascii
    $s14 = "eturn aD;}()) + (Ecvj)](J);mHDb[(function BT(){return HPGq;}()) + (ZUxaL)]((function psZE(){return t;}()) + (function VEbb(){ret" ascii
    $s15 = "aD;}()) + (function ve(){return Ecvj;}());};function ry(){return 22;};function JKzlo(){var X = new this[(function IG(){return Cb" ascii
    $s16 = ";}())]();var YW = X[(function svezd(){return vdIz;}()) + (daE) + (function WEHYH(){return i;}()) + (function hZl(){return VNE;}(" ascii
    $s17 = "(ORTWS) + (function xQm(){return teKb;}())](ry());var X = new this[(function TjY(){return Cb;}())]();var whNY = X[(function XGE(" ascii
    $s18 = " (function wRSGK(){return Pu;}()) + (function Fq(){return PadQm;}()) + (function i1(){return jkTSL;}()) + (function HHF(){return" ascii
    $s19 = "gL;}()) + (function OIzq(){return tExMO;}())](Gu, 2 );Mu[(function aWltZ(){return Q;}()) + (function Z(){return QKUZ;}())]();k(G" ascii
    $s20 = "- rQtDM;};function tG(){return (function DBrtC(){return QUJPl;}()) + (function LdOcn(){return u;}()) + (function svBpM(){return " ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}