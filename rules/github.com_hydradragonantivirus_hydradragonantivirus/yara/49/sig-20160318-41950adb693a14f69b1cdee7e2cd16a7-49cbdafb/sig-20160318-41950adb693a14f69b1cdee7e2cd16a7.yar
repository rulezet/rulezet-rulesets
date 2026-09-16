rule sig_20160318_41950adb693a14f69b1cdee7e2cd16a7 {
  meta:
    description = "datamaliciousorder - file 20160318_41950adb693a14f69b1cdee7e2cd16a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3813382d76ddeee2317acdeed9a1cebdc9c23a3e11141bb15e2a67114ae80f51"

  strings:
    $s1  = "var qIYvL = \"\\x6e!\";var fwO = \"ga\\x69\";var BrEG = \"\\x72y a\";var mVbOn = \"se, t\";var YHPu = \"ea\";var oOYcD = \"Pl\";" ascii
    $s2  = " yw;}()) + (Ka) + (h)]();WScript[(function Kc(){return ofS;}()) + (function pE(){return yV;}()) + (kmw)](BPA());var lBHg = new t" ascii
    $s3  = "mYZI(){return kmw;}())](BPA() * 10)};zbU = WScript[Rk()]((function nznV(){return EliFv;}()) + (function e0(){return uB;}()) + (u" ascii
    $s4  = "}()) + (function q(){return Rq;}())] < 4 ) {WScript[(function PJ(){return ofS;}()) + (function JKp(){return yV;}()) + (function " ascii
    $s5  = "eturn njAe;}()) : (qLGIE) + (function l1(){return Lq;}()) + (utt) + (function fzy(){return lFR;}());}else{WScript.Echo((function" ascii
    $s6  = ")); M = GqSN(); SDfN = WScript[(UTE) + (function yiP(){return vTO;}()) + (sjp) + (function xwtu(){return j;}()) + (cTd)](M);SDfN" ascii
    $s7  = "()) + (function B(){return yw;}()) + (function H(){return Ka;}()) + (function Oe(){return h;}())]();WScript[(function iicVG(){re" ascii
    $s8  = " \"e\\x4f\\x62\";var UTE = \"Crea\\x74\";var K = function nsI() {return WScript[(function NIG(){return UTE;}()) + (function Nmxe" ascii
    $s9  = "(BJT, jsc){return BJT - jsc;};function Rk(){return (function QurV(){return UTE;}()) + (function iQBc(){return vTO;}()) + (sjp) +" ascii
    $s10 = "S(){return tpgud;}()) + (function RqGcz(){return IJVf;}()) + (zCB) + (cBCS) + (mu) + (function DOcmD(){return gQNu;}()) + (funct" ascii
    $s11 = "nction zrBKN(){return y;}()) + (function Gu(){return Xv;}()) + JsZBz ? (function uzWL(){return O0;}()) + (l0) + (function sD(){r" ascii
    $s12 = "{return Vo;}()) + (function E0(){return nVUsH;}())]();while (SDfN[(function aN(){return ZXL;}()) + (function dbIkE(){return zUs;" ascii
    $s13 = " + (function hCgt(){return Dudy;}()) + (function DrqAH(){return euEHd;}()) + (function wzz(){return lDo;}()) + (function hNs(){r" ascii
    $s14 = " JeQf;}()) + (function aaz(){return SHeK;}()) + (function RMJS(){return JAA;}()) + (function v(){return h1;}()) + (function t0()" ascii
    $s15 = " ugyzS(){return oOYcD;}()) + (function KWUBc(){return YHPu;}()) + (function HjUc(){return mVbOn;}()) + (function MUjho(){return " ascii
    $s16 = " + (function zmcHM(){return vEyNW;}()) + (u) + (function Hw(){return deYr;}()) + (function OaEiT(){return mNPoT;}()) + (c) + (fu" ascii
    $s17 = "ion D(){return Rtp;}()))]();zbU[(function HaC(){return VqO;}())] = 1;zbU[(function yhLuK(){return Xc;}()) + (function CWjy(){ret" ascii
    $s18 = "{return eG;}()) + (function m0(){return ylnd;}()) + (function HOVB(){return UDk;}()) + (function BVId(){return Piqj;}()) + (func" ascii
    $s19 = "+ (function XwedA(){return yw;}()) + (function kus(){return Ka;}()) + (h)]();var NVg = \"eEeMj\";NVg = ZseDq(my, ozBpD);var SH =" ascii
    $s20 = "is[(L) + (function zVR(){return a;}())]();var ozBpD = lBHg[(function ebb(){return DQ;}()) + (vg) + (function wywpi(){return AU;}" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}