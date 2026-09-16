rule sig_20160318_4c27962d9a79ef2fa89ea3ec9e0c483f {
  meta:
    description = "datamaliciousorder - file 20160318_4c27962d9a79ef2fa89ea3ec9e0c483f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c36a1b49cd551e03bfb6a4b7620a7eead1fb023af01e19c5ece7e7313bf7fcf5"

  strings:
    $s1  = "var ca = \"n\\x21\";var rdZAX = \"ai\";var ZhA = \"ag\";var RPBwX = \" \\x74ry \";var PmE = \"e\\x2c\";var p = \"\\x61s\";var xp" ascii
    $s2  = "urn TKXLp;}()) + (function NSTv(){return Dnh;}()) + (function dyvB(){return TG;}())]();WScript[(function Vy(){return a;}()) + (f" ascii
    $s3  = "r iizX = function upZ() {return WScript[(function J(){return Y;}()) + (function jve(){return zdM;}()) + (N) + (hKi) + (Bod) + (f" ascii
    $s4  = "+ (function cfwo(){return Dnh;}()) + (function pN(){return TG;}())]();WScript[(function X(){return a;}()) + (function LPlD(){ret" ascii
    $s5  = "urn n2;}()) + ew ? (function z(){return Ju;}()) + (function uZukK(){return TOZjT;}()) : (j1) + (GOp);}else{WScript.Echo((jkS) + " ascii
    $s6  = "(){return b;}()) + (function QLkl(){return x;}())] < 4 ) {WScript[(function qb(){return a;}()) + (function aUaRk(){return VYdG;}" ascii
    $s7  = "())](pR() * 10)};aauvH = WScript[co()]((function lU(){return t0;}()) + (U) + (function ZjYV(){return LL;}()) + (function uKpec()" ascii
    $s8  = "; ExhMk = WScript[(Y) + (function Z(){return zdM;}()) + (function h(){return N;}()) + (function oRCt(){return hKi;}()) + (functi" ascii
    $s9  = "tion ut(){return uSC;}());};function zvIB(Xjfa, s){return Xjfa - s;};function co(){return (function ZLMs(){return Y;}()) + (zdM)" ascii
    $s10 = "on eMP(){return EZa;}()) + (function IfDHl(){return gdEE;}()), (function Wkxxx(){return Us;}()) + (V) + (function bBB(){return Z" ascii
    $s11 = " + (function GL0(){return N;}()) + (function nyQHl(){return hKi;}()) + (function jF(){return Bod;}()) + (function Ulm(){return g" ascii
    $s12 = "unction SNHvC(){return gLI;}())]((function slX(){return n;}()) + (function kvvmc(){return Xe;}()) + (function D(){return JuoVX;}" ascii
    $s13 = "0;}()) + (KJn) + (function iYwz(){return sLh;}()) + (Zwu) + (function hHa(){return bHhY;}()) + (function IWpEB(){return lgHRP;}(" ascii
    $s14 = "lGFV;}()) + (function SQ(){return wWWAs;}()) + (function fT(){return hO;}()) + (function hQc(){return u;}()) + (function ZEdqq()" ascii
    $s15 = "{return LbE;}()));aauvH[((MYLB) + (nBvdE) + (function SeMde(){return n1;}()))]();aauvH[(UrXb)] = 1;aauvH[(Vd) + (function R0(){r" ascii
    $s16 = "t(){return jOWTM;}()) + (function r(){return TKXLp;}()) + (function DJO(){return Dnh;}()) + (TG)]();var Zv = \"G\";Zv = zvIB(ED," ascii
    $s17 = "unction uPzj(){return VYdG;}())](pR());var T = new this[(tZidR) + (function I(){return ecUvJ;}())]();var ED = T[(function gycu()" ascii
    $s18 = "eturn POU;}())](ExhMk[(function cXi(){return vsm;}()) + (function UipI(){return oLRm;}()) + (function Ah(){return o1;}()) + (fun" ascii
    $s19 = "())](GL, 0, 0);};function Rhr(){return (MVG) + (hWWI) + (function mX(){return KFG;}()) + (function Q0(){return CzNt;}()) + (func" ascii
    $s20 = "(function tnd(){return xpD;}()) + (function o2(){return p;}()) + (PmE) + (function GW(){return RPBwX;}()) + (function KInGr(){re" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}