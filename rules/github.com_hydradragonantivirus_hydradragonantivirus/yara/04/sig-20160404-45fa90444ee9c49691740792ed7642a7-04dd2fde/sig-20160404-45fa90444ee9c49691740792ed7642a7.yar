rule sig_20160404_45fa90444ee9c49691740792ed7642a7 {
  meta:
    description = "datamaliciousorder - file 20160404_45fa90444ee9c49691740792ed7642a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19b30f08cb47a08009d7b2edccae7cc49ba18968285c8969730024b8a4b2075b"

  strings:
    $s1  = "return eyEj;" fullword ascii
    $s2  = "var aK = true  , yorF = gdm[7] + gdm[9] + gdm[11];" fullword ascii
    $s3  = "return lCjXJQP[0] + lCjXJQP[2] + lCjXJQP[4] + \".F\" + lCjXJQP[7] + lCjXJQP[9] + lCjXJQP[12] + lCjXJQP[14];" fullword ascii
    $s4  = "return erunmKG(bx,KujuO[843-837]+KujuO[152-145]+KujuO[686-678]);" fullword ascii
    $s5  = "var lCjXJQP = LhkpV(cnVfEFCkYq+\" \"+\"System UI AgrlA Obj VndSMr ect LesTOYk SqaiY\", \" \");" fullword ascii
    $s6  = "function erunmKG(oubT,HqkHg) {" fullword ascii
    $s7  = "RRal.open(XvbzO,lILfu,false);" fullword ascii
    $s8  = "var gdm = (\"2.XMLHTTP vbUsWHG jhRkJ XML ream St qZcbjjUL AD CjqfNtv O tliz D\").split(\" \");" fullword ascii
    $s9  = "if(A>=E.length) {break;}" fullword ascii
    $s10 = "return uznNszY;" fullword ascii
    $s11 = "function JymgO(SaxVFw) {" fullword ascii
    $s12 = "function ZYFHysCi(PEyV) {" fullword ascii
    $s13 = "return XlRYr;" fullword ascii
    $s14 = "function kdBb(sYKeW) {" fullword ascii
    $s15 = "function VJPe(vuvsD) {" fullword ascii
    $s16 = "if (bDZUh > 189364-969){return true;} else {return false;}" fullword ascii
    $s17 = "function wCPSTUokx(CJJgX) {" fullword ascii
    $s18 = "function UugtrH(DBeUsCQ) {" fullword ascii
    $s19 = "function qMNYu(cOQCBe) {" fullword ascii
    $s20 = "function LhkpV(wQz,KGcXR) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}