rule sig_20160318_931be27107751addbf04d363dcec4a6c {
  meta:
    description = "datamaliciousorder - file 20160318_931be27107751addbf04d363dcec4a6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8d14d5a3ef4945564e346ea4077effef81a855594acbd80c74f0fb9c5764f99"

  strings:
    $s1  = "var QzX = \"\\x21\";var cBL = \"\\x67ain\";var LrrOt = \"try\\x20\\x61\";var y0 = \",\\x20\";var a1 = \"s\\x65\";var KtR = \"Ple" ascii
    $s2  = ";}()) + (Dn);}else{WScript.Echo((KtR) + (function oyyX(){return a1;}()) + (function qevmW(){return y0;}()) + (function lud(){ret" ascii
    $s3  = "ction tBIY(){return kkCL;}()) + (function GbwP(){return xOaN;}())]();WScript[(function xw(){return CgBGd;}()) + (function Rba(){" ascii
    $s4  = "aN;}())]();WScript[(CgBGd) + (function VN0(){return fKw;}())](WH());var CSrqs = new this[(function ZdS(){return kCm;}()) + (func" ascii
    $s5  = "o = function GGKPX() {return WScript[(C) + (nX) + (DjPIG) + (function zaMS(){return jm;}())]((function j(){return UQqsw;}()) + (" ascii
    $s6  = "ction i(){return e0;}())] < 4 ) {WScript[(CgBGd) + (fKw)](WH() * 10)};fBwen = WScript[vci()]((function dZt(){return bg;}()) + (X" ascii
    $s7  = "on Fzb(){return M;}()) + (Mzne) + (function KwzKE(){return cQre;}()) + (function bjQ(){return eD;}()); F = bbB(); XK = WScript[(" ascii
    $s8  = "oVb;}()) + (VN) + (function Y(){return pdmp;}()) + (function pQMBj(){return EZLNh;}());};function VpVq(V, s){return V - s;};func" ascii
    $s9  = "lse;for (var eWue = 0; eWue < WH() * 1; eWue++){if (tr() != 0){oXE = true;IOg = true;break;}}function QfDn() {return oXE && IOg;" ascii
    $s10 = "RTVzI\"[\"charAt\"](3);var hMu = \"\\x74\\x65\";var nHRJ = \"wr\\x69\";var qBSM = \"t\\x79\\x70e\";var kYGg = \"ope\\x6e\";var X" ascii
    $s11 = "on q(){return bM;}()), false);XK[(function ZUQ(){return HnOz;}()) + (function zLHX(){return MHJs;}())]();while (XK[(mtZD) + (fun" ascii
    $s12 = "urn LrrOt;}()) + (function fj(){return cBL;}()) + (function z(){return QzX;}()));}" fullword ascii
    $s13 = "tion vci(){return (function qaVS(){return C;}()) + (function FnwQS(){return nX;}()) + (DjPIG) + (function B(){return jm;}());};f" ascii
    $s14 = "function FuHw(){return DrsO;}()) + (function nG(){return y;}()) + (function AA(){return HemD;}()) + (function j0(){return pAwDa;" ascii
    $s15 = "};if (QfDn()){eT = xzoo[(function MBIRR(){return VsiSm;}()) + (function weM(){return FCrbr;}()) + (function r(){return e;}()) + " ascii
    $s16 = "0(){return Y1;}()) + (function BZlM(){return KxycI;}()) + (k0)](eT, 2 );fBwen[(Tqs) + (function REjT(){return kL;}())]();Sf(eT);" ascii
    $s17 = "turn kuqRQ;}()) + (function k(){return a;}()) + (function PD(){return T;}()) + (function PF(){return zxfIj;}()) + (function UJQc" ascii
    $s18 = "xnE = \"\" + (function lv(){return JSl;}()) + (function u0(){return XM;}()) + (function R1(){return ITh;}()) + (function M0(){re" ascii
    $s19 = "+ (function yI(){return PXIa;}()) + (function FVp(){return gpX;}()) + (bFzc) + (function HZ(){return wLOF;}()) + (function lf(){" ascii
    $s20 = "[(function noz(){return TSL;}()) + (function mBKF(){return N;}()) + (function gvEkN(){return ntuYp;}()) + (kkCL) + (xOaN)]();var" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}