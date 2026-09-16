rule _20160322_2d5c4c35dfed45818aa962b65ea9f484_20160322_41b49c356e57_389 {
  meta:
    description = "datamaliciousorder - from files 20160322_2d5c4c35dfed45818aa962b65ea9f484.js, 20160322_41b49c356e571c01995313c815d4cfd2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfb613344c588a2660fac707e43e9e31f00da005ca1dee6b253137ef1a3331d2"
    hash2       = "f9ce7983ec4b862ec254d05414aaabeb686f91393cfd4d814d3084e0db493c33"

  strings:
    $s1  = "return WScript.CreateObject(BJoqj);" fullword ascii
    $s2  = "var JO = true  , zWvc = oRw[7] + oRw[9] + oRw[11];" fullword ascii
    $s3  = "var oRw = (\"2.XMLHTTP YegBYCu GuILE XML ream St llpnvreC AD UHGGJcN O vXEe D\").split(\" \");" fullword ascii
    $s4  = "Mzrnu.open(ABISp,apVBc,false);" fullword ascii
    $s5  = "function onQp(bUUzE) {" fullword ascii
    $s6  = "return new ActiveXObject(sMJtdc);" fullword ascii
    $s7  = "function ivaGBoZt(dJJi) {" fullword ascii
    $s8  = "return aCAhJdn[0] + aCAhJdn[2] + aCAhJdn[4] + \".F\" + aCAhJdn[7] + aCAhJdn[9] + aCAhJdn[12] + aCAhJdn[14];" fullword ascii
    $s9  = "function ZrrDXxzPg(wndoE) {" fullword ascii
    $s10 = "if (w >= oSZIg.length) {break;}" fullword ascii
    $s11 = "if (lWZjH == 370-170){return true;} else {return false;}" fullword ascii
    $s12 = "return dnYKBvG(EU,KtzUe[658-652]+KtzUe[909-902]+KtzUe[806-798]);" fullword ascii
    $s13 = "function hHTQ(OOldQ) {" fullword ascii
    $s14 = "function Dcfh(hjshK,eDyDL) {" fullword ascii
    $s15 = "function RboYg(RnD,NKSqh) {" fullword ascii
    $s16 = "GuJ = P; break; " fullword ascii
    $s17 = "function GTXc(BJoqj) {" fullword ascii
    $s18 = "return KoQUxF.position=676-676;" fullword ascii
    $s19 = "function DVNQrxpia(JKdSiLwZfjT) {" fullword ascii
    $s20 = "function GzNZPjYw(AFy) {" fullword ascii

  condition:
    ((uint16(0) == 0x0a0d or uint16(0) == 0x5357) and (8 of them)
    ) or (all of them)
}