rule sig_20160405_54829aaef3759ec0f875be05ac3ee5e4 {
  meta:
    description = "datamaliciousorder - file 20160405_54829aaef3759ec0f875be05ac3ee5e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e1fce4d95fb3744fda9375f99cd675a7a3f10f456ed2db4b37379ec0983393b"

  strings:
    $s1  = "function ubPi(EYECt,PcLfk,CEyQp) {" fullword ascii
    $s2  = "return ouymEeO[0] + ouymEeO[2] + ouymEeO[4] + \".F\" + ouymEeO[7] + ouymEeO[9] + ouymEeO[12] + ouymEeO[14];" fullword ascii
    $s3  = "var Ig = true  , cifg = RGT[7] + RGT[9] + RGT[11];" fullword ascii
    $s4  = "XozT.open(CEyQp,PcLfk,false);" fullword ascii
    $s5  = "var RGT = (\"2.XMLHTTP tWZMPiz EoWlH XML ream St WIFyioxM AD RkmSREw O SuBQ D\").split(\" \");" fullword ascii
    $s6  = "return QvQY;" fullword ascii
    $s7  = "function pshBE(ZVxyolSF,QfIJ) {" fullword ascii
    $s8  = "function vSqgYH(IlZV,nikylH) {" fullword ascii
    $s9  = "return new ActiveXObject(yGjL);" fullword ascii
    $s10 = "function BLUC(jRPYe) {" fullword ascii
    $s11 = "function QgRW(nSJVL) {" fullword ascii
    $s12 = "function Iktt(zilSW) {" fullword ascii
    $s13 = "function jIzr(jVgzl) {" fullword ascii
    $s14 = "function eXdF(iiVsx) {" fullword ascii
    $s15 = "function nFUVdO(dMgoSJe) {" fullword ascii
    $s16 = "Wxh = C; break; " fullword ascii
    $s17 = "function OJyr(bBAXs) {" fullword ascii
    $s18 = "function baTDX(gXN,KuMrp) {" fullword ascii
    $s19 = "return ZvUQH;" fullword ascii
    $s20 = "function AGHTvqX(RBPy) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}