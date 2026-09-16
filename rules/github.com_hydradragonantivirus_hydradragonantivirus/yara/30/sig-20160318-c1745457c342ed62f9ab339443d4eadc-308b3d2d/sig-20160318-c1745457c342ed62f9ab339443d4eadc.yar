rule sig_20160318_c1745457c342ed62f9ab339443d4eadc {
  meta:
    description = "datamaliciousorder - file 20160318_c1745457c342ed62f9ab339443d4eadc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7d9cf69c41e02b082f80966462847691797c0653f5f940bccfa15d8dd7c072e"

  strings:
    $s1  = "var sJQ = \"\\x6e!\";var bjZ = \"\\x67ai\";var wLFDY = \"pxboiaTIyld\"[\"charAt\"](5);var RXi = \" try\\x20\";var w2 = \"e,\";va" ascii
    $s2  = "(function m(){return sJ;}()) + (XIx) + (function LaN(){return bm;}());}else{WScript.Echo((function wgx(){return sVQ;}()) + (func" ascii
    $s3  = ") + (function PRn(){return lPs;}())]();WScript[(function c0(){return dqC;}()) + (viE)](eKH());var gblQV = new this[(function Fio" ascii
    $s4  = "PGki = WScript[b()]((function PZ(){return Fqg;}()) + (function jch(){return u;}()) + (function QabK(){return gAsgd;}()) + (funct" ascii
    $s5  = "(){return cTflz;}()) + (function rF(){return O;}()) + (function uSFV(){return lPs;}())]();WScript[(function T(){return dqC;}()) " ascii
    $s6  = "Tr)]();while (kbei[(gr) + (EFYD)] < 4 ) {WScript[(function LKU(){return dqC;}()) + (function v0(){return viE;}())](eKH() * 10)};" ascii
    $s7  = "= WScript[(function bXZD(){return dkTzm;}()) + (hByZY) + (function Bm(){return t;}()) + (U) + (function bRsTl(){return tT;}())](" ascii
    $s8  = "ea;}()) + (nes) + (o);};function TdlTy(K, cbLL){return K - cbLL;};function b(){return (function NGJ(){return dkTzm;}()) + (hByZY" ascii
    $s9  = " true;break;}}function XugfN() {return eejpW && bdaP;};if (XugfN()){BRMK = Nx[(function JLKr(){return vqNH;}()) + (function hTyr" ascii
    $s10 = " \"ct\";var U = \"Obje\";var t = \"te\";var hByZY = \"\\x72ea\";var dkTzm = \"C\";var Nx = function Kt() {return WScript[(functi" ascii
    $s11 = " this[(DiacY) + (function ebmnC(){return vCefp;}())]();var ivz = gblQV[(function FBYfn(){return czK;}()) + (GgY) + (function Umy" ascii
    $s12 = "ion d0(){return F;}()));PGki[((t0))]();PGki[(xImnJ) + (function F0(){return G;}()) + (function UHs(){return nS0;}())] = 1;PGki[(" ascii
    $s13 = "function l(){return ivTk;}()) + (function T0(){return Kb;}()) + (function tsO(){return pVtsQ;}()) + (function VyBm(){return D1;}" ascii
    $s14 = "){return oH;}())]();DHFo(BRMK);HcIE = \"\" + (function wOFc(){return sPXj;}()) + (function Axql(){return NaRpx;}()) + (function " ascii
    $s15 = "+ (function OhwU(){return viE;}())](eKH());var gblQV = new this[(function bbC(){return DiacY;}()) + (function HdkQ(){return vCef" ascii
    $s16 = "dlTy(HcIE, IJEj);}var eejpW = false;var bdaP = false;for (var xKU = 0; xKU < eKH() * 1; xKU++){if (c() != 0){eejpW = true;bdaP =" ascii
    $s17 = "C;}())] = 0;PGki[(pSj) + (A0) + (function Vif(){return ad;}()) + (function NqL(){return UOLVX;}())](BRMK, 2 );PGki[(function wo(" ascii
    $s18 = "()) + (function B(){return Fc;}()) + (a0) + eejpW ? (vLD) + (function HMC(){return eVdiB;}()) + (function HV(){return XM;}()) : " ascii
    $s19 = " (function GDz(){return zRJ;}()) + (function uIES(){return Ho;}()) + (function JSb(){return BDw;}()) + (function VdknA(){return " ascii
    $s20 = "}()) + (function HK(){return W;}()) + (POC) + (function a(){return Kzzrv;}()) + (H)]((function d(){return j;}()) + (kcn) + (func" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}