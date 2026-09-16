rule sig_20160318_115ba12f54e27e77b0579dc270d280c0 {
  meta:
    description = "datamaliciousorder - file 20160318_115ba12f54e27e77b0579dc270d280c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53d9b89017f1bb4829058e554c3e7847fcabec9e5be32cf2babc8ee52992f4b1"

  strings:
    $s1  = "var dZ = \"n!\";var GzpSX = \" ag\\x61\\x69\";var HCH = \"try\";var JhVq = \"se\\x2c \";var II = \"P\\x6ce\\x61\";var fxN = \"6" ascii
    $s2  = "return tQIs;}())] < 4 ) {WScript[(function MxgQq(){return qxPbp;}())](CBGYM() * 10)};XYy = WScript[g()]((CZ) + (function LKY(){r" ascii
    $s3  = "else{WScript.Echo((II) + (JhVq) + (function ZaIa(){return HCH;}()) + (function ebF(){return GzpSX;}()) + (dZ));}" fullword ascii
    $s4  = " {return WScript[(FYgEh) + (function tp(){return TBNnU;}()) + (e) + (Cym)]((function X(){return wt;}()) + (zbEl) + (function HxS" ascii
    $s5  = "on QVE(){return LPYMR;}()) + (function wSHj(){return sc;}()) + (function LJwE(){return vnFc;}()); CJpKC = OD(); Bw = WScript[(fu" ascii
    $s6  = "N0;}()) + (function rovY(){return m;}()) + (function lXAd(){return zIcbO;}()) + (function VFgJr(){return c0;}())]();WScript[(fun" ascii
    $s7  = "0;}()) + (function Mc(){return oIu;}()) + (function LVW(){return yv;}());};function Nfo(uHe, KyNEw){return uHe - KyNEw;};functio" ascii
    $s8  = "nOTz = true;break;}}function oP() {return dAPd && cnOTz;};if (oP()){acr = Byonn[(function c1(){return j;}()) + (function FWhG(){" ascii
    $s9  = "ction yTVU(){return c0;}())]();WScript[(function wQ(){return qxPbp;}())](CBGYM());var fzG = new this[(function PnEOK(){return Ln" ascii
    $s10 = "nction Ty(){return FYgEh;}()) + (function TvmBf(){return TBNnU;}()) + (function OTEa(){return e;}()) + (function Rc(){return Cym" ascii
    $s11 = "n g(){return (function Srrj(){return FYgEh;}()) + (function EkJVn(){return TBNnU;}()) + (function v(){return e;}()) + (function " ascii
    $s12 = "k(){return Cym;}());};function CBGYM(){return 22;};function rb(){var fzG = new this[(function pBXcR(){return LnGc;}()) + (functi" ascii
    $s13 = "on qo(){return u;}()) + (function rpP(){return N0;}()) + (function el(){return m;}()) + (function aws(){return zIcbO;}()) + (fun" ascii
    $s14 = "VBy(){return WN;}()) + (function HNVBF(){return OWu;}()) + (RAJGv) + (function dkx(){return yWXa;}()) + (Fg) + (function DUVY(){" ascii
    $s15 = "return k0;}()) + (function Ps(){return Uxo;}()) + (function SBxw(){return DeoW;}()) + (function ZCvl(){return Zgyo;}()) + (funct" ascii
    $s16 = "d(){return r;}()) + (function VS(){return UhzWz;}()) + (function UIn(){return gl;}())]);XYy[(function Q(){return qxmg;}()) + (fu" ascii
    $s17 = " N);return Nfo(ashEC, ul);}var dAPd = false;var cnOTz = false;for (var F = 0; F < CBGYM() * 1; F++){if (rb() != 0){dAPd = true;c" ascii
    $s18 = "kC(){return zIcbO;}()) + (function BgG(){return c0;}())]();var ashEC = \"JbKfG\";ashEC = Nfo(N, bx);var ul = \"Rzl\";ul = Nfo(kv" ascii
    $s19 = "nction juH(){return yR;}()) + (bhc) + (function FpnBv(){return SZ;}())] = 0;XYy[(function YSyb(){return H;}()) + (yKk) + (MavO)]" ascii
    $s20 = " = \"\" + (function imHe(){return A;}()) + (function oQ(){return yLo;}()) + (HP) + (function u0(){return SSaAw;}()) + (function " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}