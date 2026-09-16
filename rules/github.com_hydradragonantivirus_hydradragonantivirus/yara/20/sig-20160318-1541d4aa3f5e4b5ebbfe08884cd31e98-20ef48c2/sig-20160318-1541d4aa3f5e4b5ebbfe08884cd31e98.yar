rule sig_20160318_1541d4aa3f5e4b5ebbfe08884cd31e98 {
  meta:
    description = "datamaliciousorder - file 20160318_1541d4aa3f5e4b5ebbfe08884cd31e98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21bf64d967b421872dfa483d70e8c6b44a76188d71586e31c319861cdde17bf7"

  strings:
    $s1  = "var aA = \"!\";var ckqB = \"ai\\x6e\";var SlFH = \"y ag\";var nm0 = \"tr\";var F = \"ujyM df\"[\"charAt\"](4);var sbQa = \"\\x61" ascii
    $s2  = " coBs;}()) + (Yi) + (g0) + (function dyN(){return Sg;}()) + (function Kc(){return cjPtA;}())]();WScript[(function q(){return W;}" ascii
    $s3  = "n XcUDq;}())]();while (Yx[(function iMvke(){return hGpmy;}()) + (function OOOk(){return E0;}()) + (xDHm)] < 4 ) {WScript[(functi" ascii
    $s4  = "\"\\x65\\x61t\\x65O\";var thLFj = \"Cr\";var qrLBI = function wZrOU() {return WScript[(function xqUsK(){return thLFj;}()) + (fun" ascii
    $s5  = "(wxqt) + (kXqI) + (Bxg); RzyJz = JxVNe(); Yx = WScript[(function fUuh(){return thLFj;}()) + (function iAszg(){return cwB;}()) + " ascii
    $s6  = "on ZRxw(){return W;}()) + (V)](cESwP() * 10)};ii = WScript[nms()]((h0) + (function uVRT(){return neLw;}()) + (function wOb(){ret" ascii
    $s7  = ") + (ZL);}else{WScript.Echo((function iwUI(){return LSZm;}()) + (sbQa) + (function lHoyf(){return F;}()) + (function muFMp(){ret" ascii
    $s8  = "}()) + (function ve(){return Sg;}()) + (function Gvo(){return cjPtA;}())]();WScript[(function fjK(){return W;}()) + (function TH" ascii
    $s9  = "return 22;};function mymu(){var hLY = new this[(function fuBFO(){return HwM;}()) + (function FtP(){return qCZ;}())]();var YF = h" ascii
    $s10 = "nction z(){return Jb;}());};function MGSbz(DUm, SFcUm){return DUm - SFcUm;};function nms(){return (function niPp(){return thLFj;" ascii
    $s11 = "](0);var taaR = \"2PWchGM\"[\"charAt\"](3);var Nwn = \"je\";var fmoF = \"b\";var uoS = \"eO\";var lgRu = \"AStaMF\"[\"charAt\"](" ascii
    $s12 = "rn c0;}()) + (qhD) : (cOuH) + (function pRc(){return eXmds;}()) + (function lmZ(){return HF;}()) + (function wVi(){return uH;}()" ascii
    $s13 = "urn feF;}()) + (function RFJfG(){return KzXi;}()) + (function hGQ(){return CK;}()) + (Y));ii[((function e0(){return FsRKe;}()) +" ascii
    $s14 = "QLz(){return vlc;}()) + (lRs) + (Khx) + (IcX) + (function Z0(){return IPshU;}()) + (function nZz(){return FFivR;}()) + (function" ascii
    $s15 = "Dh){qrLBI[(SyqB)](Dh, 0, 0);};function JxVNe(){return (function SD(){return ow;}()) + (R) + (function gp(){return WJX;}()) + (fu" ascii
    $s16 = "tion g(){return CDb;}()) + (function RAA(){return tdG;}()) + (wpl) + (function hkDZ(){return CEtz;}()) + (cQNX));}();function i(" ascii
    $s17 = "LY[(function Kk(){return E;}()) + (function OZNS(){return coBs;}()) + (function gREb(){return Yi;}()) + (function O(){return g0;" ascii
    $s18 = " gah(){return A;}()) + (function bmw(){return j;}()) + (function qPCbm(){return j0;}()), false);Yx[(T) + (function QWnjF(){retur" ascii
    $s19 = "}()) + (function TtjLr(){return cwB;}()) + (function AsTX(){return t;}()) + (function cF(){return jeJUZ;}());};function cESwP(){" ascii
    $s20 = "(){return V;}())](cESwP());var hLY = new this[(function aQTB(){return HwM;}()) + (qCZ)]();var d = hLY[(E) + (function H(){return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}