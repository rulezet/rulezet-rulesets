rule sig_20160318_4933054e46182366fc7854aaf5d2a096 {
  meta:
    description = "datamaliciousorder - file 20160318_4933054e46182366fc7854aaf5d2a096.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5ecbee6c0f28e637361849dd91b9c8f5e75747cc8c882b3181845f1d6bb78f6"

  strings:
    $s1  = "var VNvs = \"n!\";var e1 = \"ai\";var T = \"y ag\";var iS = \" tr\";var opkF = \"\\x61se\\x2c\";var VsAfY = \"Pl\\x65\";var WyNy" ascii
    $s2  = "ion vPvL(){return glzO;}()) + (su0)]();WScript[(function Svm(){return zt;}())](mlvTv());var LvUl = new this[(Fe)]();var lIfBP = " ascii
    $s3  = "\";var DUQm = \"t\\x65O\";var BuhAX = \"Cr\\x65a\";var D = function zxHI() {return WScript[(function dS(){return BuhAX;}()) + (f" ascii
    $s4  = "return fpE;}()) + (function Pcv(){return CYjhp;}()) + (function hix(){return ebny;}()) + (cob)] < 4 ) {WScript[(function ow(){re" ascii
    $s5  = "zO;}()) + (su0)]();WScript[(zt)](mlvTv());var LvUl = new this[(Fe)]();var QYpA = LvUl[(function ADF(){return n;}()) + (function " ascii
    $s6  = "turn zt;}())](mlvTv() * 10)};XSn = WScript[YZr()]((sW) + (function AS(){return YRFXb;}()) + (QLDGo) + (function OM(){return sgYj" ascii
    $s7  = "n wm;}()) + (function gy(){return AFtq;}()) + (function ki(){return ov;}()) + (oTE); BDmg = olab(); whZe = WScript[(function NB(" ascii
    $s8  = "}else{WScript.Echo((function x(){return VsAfY;}()) + (function Vhq(){return opkF;}()) + (iS) + (function Wk(){return T;}()) + (f" ascii
    $s9  = "rn (Hj) + (function rmZun(){return wyKql;}()) + (yAD) + (function TGNCl(){return S0;}()) + (KG);};function o(BE, S){return BE - " ascii
    $s10 = "or (var ly = 0; ly < mlvTv() * 1; ly++){if (Olgu() != 0){qvNV = true;hOOVP = true;break;}}function RYfxz() {return qvNV && hOOVP" ascii
    $s11 = "LvUl[(function DutyT(){return n;}()) + (function g(){return GMKV;}()) + (function j(){return jR;}()) + (function oRO(){return gl" ascii
    $s12 = "eturn mWV;}()) + (function kjI(){return KStTw;}())) + (jq) + (UC) + (function Ujet(){return JtsLI;}()) + (function ETlIW(){retur" ascii
    $s13 = "g;}()));XSn[((L) + (function e(){return HInNo;}()))]();XSn[(function cnYA(){return h;}()) + (Y)] = 1;XSn[(function icsSw(){retur" ascii
    $s14 = "){return BuhAX;}()) + (function XkWR(){return DUQm;}()) + (sR) + (owc)](BDmg);whZe[(L) + (function kSnQI(){return HInNo;}())]((f" ascii
    $s15 = ";}()) + (zWBYC) + (function jDZL(){return Q0;}()) + (H) + (bX) + (function KeVgW(){return mMQ;}()) + (function GVI(){return dKO;" ascii
    $s16 = ";};if (RYfxz()){ku = D[(function YmIlQ(){return RHPk;}()) + (function dwRQv(){return d;}()) + (function sA(){return Gocf;}()) + " ascii
    $s17 = "AEc(){return GMKV;}()) + (function GtYH(){return jR;}()) + (function Omq(){return glzO;}()) + (function aTi(){return su0;}())]()" ascii
    $s18 = "S;};function YZr(){return (function wo(){return BuhAX;}()) + (function ldUDW(){return DUQm;}()) + (function su(){return sR;}()) " ascii
    $s19 = "Eoc(){return TKIm;}()) + (function puC(){return e0;}()), false);whZe[(function s(){return io;}())]();while (whZe[(function V0(){" ascii
    $s20 = "}()) + qvNV ? (function m(){return Bli;}()) + (function YUAbV(){return fjJ;}()) : (function v(){return BtT;}()) + (pt) + (WyNy);" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}