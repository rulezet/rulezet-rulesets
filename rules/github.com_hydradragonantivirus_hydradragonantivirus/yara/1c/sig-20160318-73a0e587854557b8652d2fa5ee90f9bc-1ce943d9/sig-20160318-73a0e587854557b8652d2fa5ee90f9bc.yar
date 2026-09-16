rule sig_20160318_73a0e587854557b8652d2fa5ee90f9bc {
  meta:
    description = "datamaliciousorder - file 20160318_73a0e587854557b8652d2fa5ee90f9bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17413717ea91559ce0a4727631004e6c313646e787c6aaa83ba29dbff9ab43ee"

  strings:
    $x1  = "var PNrd = \"\\x6e\\x21\";var EpZy = \"a\\x67\\x61i\";var Pich = \"\\x20t\\x72y \";var Cy = \"1TIu,\"[\"charAt\"](4);var GPpzr =" ascii
    $s2  = "\\x72e\\x61\";var Es = \"CJ\"[\"charAt\"](0);var g = function Rdr() {return WScript[(function M(){return Es;}()) + (function HDz" ascii
    $s3  = " ibVwM;}()) + (function orED(){return M0;}()) + (DTEE) + (function wo(){return FC;}())]();WScript[(GR)](mVduU());var U = new thi" ascii
    $s4  = " : (function u0(){return xuT;}()) + (rdSE);}else{WScript.Echo((function q(){return Nlspg;}()) + (TYS) + (function qJh(){return G" ascii
    $s5  = "()) + (function tnjxN(){return hlmMw;}()) + (function OxhEg(){return ubB;}())] < 4 ) {WScript[(GR)](mVduU() * 10)};d = WScript[d" ascii
    $s6  = "+ (function a(){return ibVwM;}()) + (function Y0(){return M0;}()) + (function diVeZ(){return DTEE;}()) + (FC)]();WScript[(GR)](m" ascii
    $s7  = "ction cczI(){return gWTm;}()) + (function cgrI(){return scu;}()) + (vtK) + (hG); nTDY = zIX(); V = WScript[(function NY(){return" ascii
    $s8  = "return vfRq;}()) + (function CeNA(){return y;}()) + (function Lijz(){return hilyR;}());};function CH(glQO, nAi){return glQO - nA" ascii
    $s9  = " < mVduU() * 1; LMFg++){if (Lc() != 0){CW = true;C = true;break;}}function z() {return CW && C;};if (z()){bteL = g[(function XXb" ascii
    $s10 = "charAt\"](5);var srA = \"MP%\";var u = \"%TE\";var V0 = \"ngs\";var CLAw = \"i\";var T0 = \"n\\x74\\x53tr\";var sVl = \"ronme\";" ascii
    $s11 = "{return Iw;}()));d[((w))]();d[(function jSG(){return Q;}()) + (function l0(){return lqs;}())] = 1;d[(function pcOQM(){return Fqx" ascii
    $s12 = "urn FVU;}()) + (function LpdO(){return AcBA;}());};function mVduU(){return 22;};function Lc(){var U = new this[(function E(){ret" ascii
    $s13 = "oq;}()) + (RFQd)](V[(function ChF(){return aktQc;}()) + (function NXknG(){return nq;}()) + (function wvDZI(){return CeqF;}())]);" ascii
    $s14 = "VduU());var U = new this[(zEBWf) + (function BbDQ(){return paH;}())]();var JSq = U[(function TM(){return edPBc;}()) + (function " ascii
    $s15 = "i;};function dUGK(){return (function vUjC(){return Es;}()) + (Ei) + (function EJgLs(){return WO;}()) + (FY) + (function d1(){ret" ascii
    $s16 = "n zK;}()) + (en) + (function wzrD(){return pf;}()) + CW ? (function IsErw(){return juEJ;}()) + (function qabFF(){return FRn;}())" ascii
    $s17 = "turn Ei;}()) + (WO) + (function rcI(){return FY;}()) + (function mREvJ(){return FVU;}()) + (function biFNF(){return AcBA;}())]((" ascii
    $s18 = "return L;}()) + (function IhW(){return csHKc;}()), false);V[(function tv(){return n;}())]();while (V[(function QBn(){return SH;}" ascii
    $s19 = "ction bHXD(){return w0;}()) + (function bgeY(){return Jn;}())](bteL, 2 );d[(iE) + (function RLVgU(){return exMVs;}()) + (functio" ascii
    $s20 = "d[(function yR(){return Iuiw;}()) + (qoqy) + (function MYmw(){return MGQko;}())] = 0;d[(function rZqfD(){return haiT;}()) + (fun" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}