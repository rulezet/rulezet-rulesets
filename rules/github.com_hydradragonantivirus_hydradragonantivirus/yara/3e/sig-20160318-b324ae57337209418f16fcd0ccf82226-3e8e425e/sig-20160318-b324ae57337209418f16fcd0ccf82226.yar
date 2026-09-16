rule sig_20160318_b324ae57337209418f16fcd0ccf82226 {
  meta:
    description = "datamaliciousorder - file 20160318_b324ae57337209418f16fcd0ccf82226.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb521e6858d95077a32f4cf77285450f5913f9f1721bf52e68ea85d031d9bfff"

  strings:
    $s1  = "var Cvhk = \"EN!Vp\"[\"charAt\"](2);var yLLZ = \"ag\\x61\\x69\\x6e\";var MGYp = \"y \";var CnF = \"e\\x2c \\x74r\";var C = \"Ple" ascii
    $s2  = "nction T(){return Fv;}())] < 4 ) {WScript[(QaAiY) + (function f0(){return UR;}())](ZwNe() * 10)};fyfYN = WScript[rlJm()]((functi" ascii
    $s3  = " = \"Cr\";var uhwA = function CJ() {return WScript[(function jcuA(){return WOIE;}()) + (function UdlF(){return r;}()) + (aH) + (" ascii
    $s4  = "{return KZ;}()); wU = CSmJ(); P = WScript[(function SAT(){return WOIE;}()) + (function O0(){return r;}()) + (function yMq(){retu" ascii
    $s5  = "unction f(){return mFz;}())]();WScript[(QaAiY) + (function XEPxY(){return UR;}())](ZwNe());var sm = new this[(xv)]();var qd = sm" ascii
    $s6  = "lse{WScript.Echo((function Ek(){return C;}()) + (CnF) + (function xZKOb(){return MGYp;}()) + (function SL(){return yLLZ;}()) + (" ascii
    $s7  = "on E(){return fn;}()) + (function Szy(){return B;}()) + (CStO) + (RcBHH) + (function QqcT(){return v0;}()) + (mFz)]();WScript[(f" ascii
    $s8  = "()) + (function Ka(){return uh;}()) + (function I(){return R0;}());};function llkUO(P0, grI){return P0 - grI;};function rlJm(){r" ascii
    $s9  = "se;var Ub = false;for (var BY = 0; BY < ZwNe() * 1; BY++){if (D() != 0){GXN = true;Ub = true;break;}}function lyv() {return GXN " ascii
    $s10 = " + (tACO) + (function xIT(){return H;}()), false);P[(function E0(){return fIxfS;}()) + (fpWXl) + (function WHWR(){return OFt;}()" ascii
    $s11 = " + (function Ed(){return A;}()) + (function R(){return vJdB;}()));}();function V(xnZp){uhwA[(function wrzRx(){return IC;}()) + (" ascii
    $s12 = ")) + (function bZpW(){return qlKW;}()) + (KKrd) + (function nI(){return xyk;}()) + (function hsYZW(){return SBDr;}())]((yvhLN) +" ascii
    $s13 = ";}()) + (function Eq(){return RvHIY;}()) + (function REf(){return i1;}()) + (jz) + (function pPYR(){return xBw;}()) + (function " ascii
    $s14 = ")]();while (P[(function I0(){return ifSaI;}()) + (rpZpq) + (function E1(){return om;}()) + (function ydXLs(){return j;}()) + (fu" ascii
    $s15 = "on m0(){return PsH;}()) + (function i0(){return xw;}()) + (function vd(){return LoLp;}()));fyfYN[((function Uuu(){return CNw;}()" ascii
    $s16 = "on ZJZw(){return czywt;}())](P[(SMv) + (function IG(){return eTexS;}()) + (function JbIfU(){return VoRsx;}())]);fyfYN[(function " ascii
    $s17 = " (cfBe) + (function sNuT(){return W0;}())) + (function VsP(){return spgF;}()) + (function aJkn(){return tI;}()) + (function wQ()" ascii
    $s18 = "eturn v0;}()) + (mFz)]();var i = \"L\";i = llkUO(vgYcw, RB);var N = \"xZuZs\";N = llkUO(qd, vgYcw);return llkUO(i, N);}var GXN =" ascii
    $s19 = ") + (function jdh(){return quN;}()))]();fyfYN[(function BA(){return io;}())] = 1;fyfYN[(function zlK(){return XqK;}()) + (functi" ascii
    $s20 = "SQH;}()) + (function xDOZt(){return AX;}()) + (Dz) + (function cbFc(){return fuH;}()) + (function OPYDm(){return o;}()) + (hdIy)" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}