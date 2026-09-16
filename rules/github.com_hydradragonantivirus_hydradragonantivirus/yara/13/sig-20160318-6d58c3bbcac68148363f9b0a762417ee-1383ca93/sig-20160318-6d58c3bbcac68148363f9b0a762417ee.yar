rule sig_20160318_6d58c3bbcac68148363f9b0a762417ee {
  meta:
    description = "datamaliciousorder - file 20160318_6d58c3bbcac68148363f9b0a762417ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbeddd4b70de84d43a95b76bd497fb935f75c9f20331c0a61cbac53ef406d51e"

  strings:
    $x1  = "var fbnXx = \"\\x21\";var L2 = \"again\";var cJZ = \"try \";var kx = \"ase, \";var phI = \"Ple\";var OidJx = \"\\x31\\x362\";var" ascii
    $s2  = "= WScript[aHIT()]((function xJ(){return NcC;}()) + (function N(){return HCR;}()) + (function axc(){return A1;}()) + (function rB" ascii
    $s3  = ") + (function p(){return MukP;}()) + (LAe); IQ = YmYP(); et = WScript[(function MfE(){return JU;}()) + (function gcfwZ(){return " ascii
    $s4  = "WScript[(function W(){return fak;}()) + (function cY(){return ojftI;}()) + (function TW(){return alY;}())](nhhjR() * 10)};oFiSh " ascii
    $s5  = "]();WScript[(fak) + (function nse(){return ojftI;}()) + (alY)](nhhjR());var S = new this[(WrCbn) + (aeniV) + (function UTACi(){r" ascii
    $s6  = "()) + (zpsm) + (function dyltp(){return uVK;}())]();WScript[(fak) + (ojftI) + (function VJkqo(){return alY;}())](nhhjR());var S " ascii
    $s7  = ";}());}else{WScript.Echo((function jZh(){return phI;}()) + (kx) + (function pD(){return cJZ;}()) + (function w(){return L2;}()) " ascii
    $s8  = "unction mXHGh(ISbvS, zqC){return ISbvS - zqC;};function aHIT(){return (function y(){return JU;}()) + (function zYnX(){return C;}" ascii
    $s9  = " = 0; QWt < nhhjR() * 1; QWt++){if (KiRY() != 0){qOgn = true;SjCEh = true;break;}}function wtKEu() {return qOgn && SjCEh;};if (w" ascii
    $s10 = "WSc\\x72\";var ja = \"t\";var Fwrds = \"c\";var C = \"eObje\";var JU = \"Cr\\x65at\";var xDSeg = function PXYpA() {return WScrip" ascii
    $s11 = "(function ZtQx(){return u;}()) + (pdVJh) + (function nySdb(){return Y;}())) + (function wvX(){return dzdSf;}()) + (function H(){" ascii
    $s12 = "(){return wuk;}()) + (function JtI(){return CZ;}()));}();function FEvnD(hUnls){xDSeg[(PVw)](hUnls, 0, 0);};function YmYP(){retur" ascii
    $s13 = "= new this[(WrCbn) + (function pDsC(){return aeniV;}()) + (function SY(){return NQPRL;}())]();var OhRG = S[(l) + (Ojdey) + (func" ascii
    $s14 = " GZKTK(){return JU;}()) + (C) + (Fwrds) + (ja)]((function b(){return wxj;}()) + (function FBTNQ(){return oj;}()) + (function vUJ" ascii
    $s15 = ";}()) + (vysu) + (function M(){return nHAJT;}()), false);et[(function GsIno(){return V0;}()) + (function tmnQH(){return id;}())]" ascii
    $s16 = "C;}()) + (function JwFPs(){return Fwrds;}()) + (ja)](IQ);et[(function sum(){return sG;}()) + (function BwI(){return k1;}()) + (f" ascii
    $s17 = "()) + (function ndqdT(){return Fwrds;}()) + (ja);};function nhhjR(){return 22;};function KiRY(){var S = new this[(function lgUsc" ascii
    $s18 = "+ (function qj(){return fbnXx;}()));}" fullword ascii
    $s19 = "unction iEVw(){return hndB;}())](JYtVH, 2 );oFiSh[(fyoC) + (function eLh(){return GV;}())]();FEvnD(JYtVH);zcrmA = \"\" + (XefN) " ascii
    $s20 = "eturn RS;}()) + (wFM) + (function qgfb(){return A0;}()) + (function nFTV(){return L0;}()) + (gW) + (function pHNb(){return mdDvl" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}