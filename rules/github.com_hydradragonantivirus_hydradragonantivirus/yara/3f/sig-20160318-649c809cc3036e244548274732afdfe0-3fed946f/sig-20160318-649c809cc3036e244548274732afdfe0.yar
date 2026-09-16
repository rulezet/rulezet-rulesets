rule sig_20160318_649c809cc3036e244548274732afdfe0 {
  meta:
    description = "datamaliciousorder - file 20160318_649c809cc3036e244548274732afdfe0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "787f0c82d9c6788bc3bbd579ff77d102b5a0a31cd5579504fecd012b875492b1"

  strings:
    $x1  = "var j1 = \"g\\x61i\\x6e!\";var jgk = \"\\x74\\x72y \\x61\";var uBxc = \",\\x20\";var u0 = \"s\\x65\";var xrFsl = \"lea\";var W =" ascii
    $s2  = "ot() {return WScript[(function pjZEX(){return FfaP;}()) + (function aMmB(){return dr;}()) + (function cng(){return K;}()) + (fun" ascii
    $s3  = ") + (function a1(){return NPkLc;}()) + (function pL(){return jhg;}())] < 4 ) {WScript[(function lhj(){return hE;}()) + (QB)](LjY" ascii
    $s4  = " s[(function tuwuX(){return fJe;}()) + (HAjzX) + (qWaD) + (xNBx)]();WScript[(hE) + (function AAS(){return QB;}())](LjYbZ());var " ascii
    $s5  = "(function vIH(){return qWaD;}()) + (xNBx)]();WScript[(hE) + (function iCw(){return QB;}())](LjYbZ());var s = new this[(MjNN)]();" ascii
    $s6  = "(){return n;}()) + (function ubt(){return IUSUj;}()) + (yjuE) : (j0) + (function fB(){return CFM;}());}else{WScript.Echo((W) + (" ascii
    $s7  = "bZ() * 10)};b = WScript[nIr()]((function Gf(){return NyjwP;}()) + (function Lg(){return AskI;}()) + (function ntq(){return IFSE;" ascii
    $s8  = "= WScript[(function RVv(){return FfaP;}()) + (function ZMmM(){return dr;}()) + (function k(){return K;}()) + (function U(){retur" ascii
    $s9  = " + (function Y(){return Eof;}()) + (function GAVpi(){return Og;}());};function vKZ(PNs, oug){return PNs - oug;};function nIr(){r" ascii
    $s10 = " * 1; kMnlX++){if (m() != 0){Rsam = true;PN = true;break;}}function L() {return Rsam && PN;};if (L()){jV = ZycXU[(A) + (function" ascii
    $s11 = " auB(){return SrpMI;}()) + (function as(){return b0;}()) + (function SsUXQ(){return X;}()) + (function q(){return zF;}()) + (fun" ascii
    $s12 = "BC;}()) + (function E(){return uod;}())] = 0;b[(function lS0(){return MQO;}()) + (function ANrsI(){return o;}()) + (function jsb" ascii
    $s13 = "ction igMQ(){return BQX;}()) + (function c0(){return zIz;}()) + (function uNC(){return qjTbk;}())]((ZUDIU) + (function xhLB(){re" ascii
    $s14 = "(YriG) + (function wzxuN(){return eo;}()) + (function u(){return rGIP;}()) + (function Q(){return cWtUK;}()) + (Y0) + (function " ascii
    $s15 = "PP;}())](MWZx[(function idJMu(){return J;}()) + (function cOhHY(){return mLNrz;}()) + (function LOWbt(){return AuM;}()) + (funct" ascii
    $s16 = "n OzbHg;}()) + (RhQrp)](PWl);MWZx[(function vXClK(){return oScg;}())]((function lS(){return wZSF;}()) + (function kx(){return mI" ascii
    $s17 = "tion B(L0){ZycXU[(function xhWuM(){return aCx;}())](L0, 0, 0);};function szM(){return (function fSow(){return ohtLL;}()) + (Fqb)" ascii
    $s18 = "A(){return Q0;}())](jV, 2 );b[(function Du(){return ymzG;}()) + (function BEea(){return gL;}())]();B(jV);cmPw = \"\" + (XOiqL) +" ascii
    $s19 = "d;}()) + (YBpWB) + (function RiQ(){return JQwyD;}()) + (Hmb) + (nuzNM) + (function vOEXX(){return tBkAq;}()); PWl = szM(); MWZx " ascii
    $s20 = "oPb;}()) + (function sa(){return Rp;}()), (function aD(){return vbLJ;}()) + (cCgOa) + (GhSZp) + (function aV(){return Ko;}()) + " ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}