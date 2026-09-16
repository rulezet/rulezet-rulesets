rule sig_20160318_69de7f5c2d03875fe00364c21b22d024 {
  meta:
    description = "datamaliciousorder - file 20160318_69de7f5c2d03875fe00364c21b22d024.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6d157ba8dcd5b6166e018079ea8fbd1670bab518644f7b9788e038e387234db"

  strings:
    $x1  = "var RTbf = \"\\x61i\\x6e!\";var wHWzi = \" ag\";var yweMa = \"\\x79\";var X6 = \"\\x74r\";var N1 = \"53OS pxm\"[\"charAt\"](4);v" ascii
    $s2  = "WScript[(function N(){return iE;}())](PcJ());var V = new this[(function q(){return Tolg;}()) + (function DMVq(){return Y;}())]()" ascii
    $s3  = "ion RgPM(){return fgDg;}()); oPMb = wAi(); H = WScript[(function VOEXv(){return uMgH;}()) + (function ejNPL(){return Ys;}()) + (" ascii
    $s4  = ") + (function aX(){return NQlvb;}())] < 4 ) {WScript[(function eJX(){return iE;}())](PcJ() * 10)};uK = WScript[vGQ()]((function " ascii
    $s5  = ";var bPRU = function Ld() {return WScript[(function P(){return uMgH;}()) + (function a(){return Ys;}()) + (function nVw(){return" ascii
    $s6  = "rc(){return T1;}()) + (function UEciV(){return dnNiT;}()) + (function EvtJl(){return NP;}());}else{WScript.Echo((zcn) + (functio" ascii
    $s7  = "ion fbl(){return Gl;}()) + (function OoLp(){return r;}()) + (function je(){return Bm;}());};function ZCRbz(o, upOJP){return o - " ascii
    $s8  = "}function NA() {return srzw && S;};if (NA()){cRFzF = bPRU[(function Dge(){return byr;}()) + (function FIBMm(){return ILLXO;}()) " ascii
    $s9  = "(function wOUeH(){return VYw;}())]();WScript[(function uzV(){return iE;}())](PcJ());var V = new this[(function lxODy(){return To" ascii
    $s10 = "y = \".XM\";var d = \"\\x32\";var V0 = \"M\\x53X\\x4d\\x4c\";var rVOXZ = \"Run\";var jUef = \"ll\";var NwdSK = \"She\";var C = " ascii
    $s11 = "r T0 = \"a\\x76eT\";var sImAl = \"ZCv60ShHYVJ\"[\"charAt\"](5);var euvo = \"\\x69\\x6fn\";var P0 = \"sit\";var O0 = \"o\";var lu" ascii
    $s12 = "nyzCE;}()) + (function PCt(){return X4;}())](cRFzF, 2 );uK[(function Bq(){return GhE;}()) + (function FXqIg(){return NEZ;}())]()" ascii
    $s13 = "eturn EX;}()) + (function K1(){return sbDLz;}()) + (function Xq(){return w;}()) + (function DFHPo(){return XF;}()) + (function Q" ascii
    $s14 = " + (function OfzfA(){return HF;}()) + (function lpdM(){return tbm;}()) + (function ru(){return saxhV;}()) + (ZHG) + (function u(" ascii
    $s15 = "unction lmrp(){return C0;}()), false);H[(function RsEGb(){return QqI;}())]();while (H[(function ZnIb(){return TQvwj;}()) + (utkn" ascii
    $s16 = "qs) + srzw ? (function eckGK(){return tu;}()) + (function Gpfy(){return B1;}()) + (function YVJ(){return okCeo;}()) : (function " ascii
    $s17 = "lg;}()) + (function ral(){return Y;}())]();var EQb = V[(function K(){return mMqZ;}()) + (Ga) + (function nv(){return E;}()) + (v" ascii
    $s18 = "n A;}())] = 1;uK[(function QdahW(){return g;}()) + (function m(){return e;}()) + (k) + (function PniK(){return J;}())](H[(functi" ascii
    $s19 = " + (function ArVah(){return NwdSK;}()) + (function l0(){return jUef;}()));}();function NNRpd(utNd){bPRU[(function vlswV(){return" ascii
    $s20 = "QN(){return Ux;}()) + (function uc(){return Y0;}()) + (function l1(){return ydh;}()) + (function Xl(){return KF;}()) + (XR) + (f" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}