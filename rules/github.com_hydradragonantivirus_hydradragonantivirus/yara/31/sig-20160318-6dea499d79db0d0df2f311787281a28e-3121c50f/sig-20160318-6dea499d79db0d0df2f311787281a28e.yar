rule sig_20160318_6dea499d79db0d0df2f311787281a28e {
  meta:
    description = "datamaliciousorder - file 20160318_6dea499d79db0d0df2f311787281a28e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfd22790e01452eb3b621a20537b736eb90291cf4a1a733ad2a652e11b558cad"

  strings:
    $s1  = "var yX = \"i\\x6e!\";var jBAOP = \" \\x61g\\x61\";var a1 = \",\\x20try\";var DoYca = \"\\x65\\x61s\\x65\";var ktD = \"Pl\";var n" ascii
    $s2  = " hti = \"eO\";var I = \"reat\";var Ameiu = \"iWzC\"[\"charAt\"](3);var rUDLf = function HskI() {return WScript[(function UxTBk()" ascii
    $s3  = "Prd;}())] < 4 ) {WScript[(function Vwh(){return wvWHF;}()) + (function gO(){return m;}())](o() * 10)};Cz = WScript[OqZbV()]((fun" ascii
    $s4  = " + (function bXSY(){return TA;}()) : (function e(){return fbUI;}()) + (KEuh) + (n);}else{WScript.Echo((function FE(){return ktD;" ascii
    $s5  = ";}())]();WScript[(function iQ(){return wvWHF;}()) + (m)](o());var GUpg = new this[(function S0(){return Cyj;}()) + (function Vor" ascii
    $s6  = ") + (function Dk(){return Lxm;}()) + (function SR(){return et;}()) + (Ln) + (VEMPC); w = dIn(); kcQu = WScript[(function DAUS(){" ascii
    $s7  = "){return XSzY;}()) + (zaHvR) + (function al(){return irWj;}()) + (function zv(){return ET;}())]();WScript[(function UFA(){return" ascii
    $s8  = ");};function dIn(){return (Hhte) + (function Gs(){return kL;}()) + (WZUyJ) + (qEYbc);};function BsN(K, bIw){return K - bIw;};fun" ascii
    $s9  = "e;for (var YF = 0; YF < o() * 1; YF++){if (EqEf() != 0){CSdD = true;ytj = true;break;}}function eBWo() {return CSdD && ytj;};if " ascii
    $s10 = "R = \"c\\x6f\\x6ed\";var Eb = \"\\x65\";var qOj = \"l\\x6cis\";var Z = \"\\x67e\\x74\\x4di\";var AwIN = \"4qJe9\"[\"charAt\"](3)" ascii
    $s11 = "rn fP;}())]((function agfUn(){return pQ;}()) + (function P(){return GUWr;}()) + (PG) + (function i0(){return ymSHm;}())) + (IdfJ" ascii
    $s12 = "SBZEA(){return N1;}()) + (function fYCBr(){return kzlV;}())](PmS, 2 );Cz[(VEBT) + (function qp(){return kt;}())]();gN(PmS);J = " ascii
    $s13 = "[(wEx) + (function osvin(){return Z0;}())]((function ysrN(){return luQ;}()) + (function XX(){return JGWaz;}()), (function IBQ(){" ascii
    $s14 = "(eBWo()){PmS = rUDLf[(function iJukD(){return N;}()) + (function KvnW(){return fCwT;}()) + (function IvBog(){return pL;}()) + (Y" ascii
    $s15 = "ion Po(){return jR;}()) + (cfI) + (function Xyp(){return HtJl;}())] = 0;Cz[(function EgqQ(){return bmW;}()) + (HVd) + (function " ascii
    $s16 = "R0(){return Pzs;}())]();while (kcQu[(function swJk(){return zISr;}()) + (function SiVLL(){return jD;}()) + (function c(){return " ascii
    $s17 = "aXG) + (function hHTE(){return Ms;}()) + (function mz(){return a0;}()) + (function Qp(){return Dqj;}()) + (function EAbUC(){retu" ascii
    $s18 = "return dz;}()) + (Mygrs) + (function Bi(){return SO;}()) + (function uP(){return NaK;}()) + (function KooJh(){return IT;}()) + (" ascii
    $s19 = "\" + (function HFYcR(){return N2;}()) + (function Ik(){return bS;}()) + (function LEGkY(){return gZBuB;}()) + (function g(){retu" ascii
    $s20 = "){return Tji;}()) + (MEX) + (mAKRq) + (function uykL(){return xxn;}()) + CSdD ? (HoB) + (dfomg) + (function cei(){return Qq;}())" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}