rule sig_20160308_91fb14112d5b7dc0b61bc04c0c09a398 {
  meta:
    description = "datamaliciousorder - file 20160308_91fb14112d5b7dc0b61bc04c0c09a398.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53f0d05b4de1bd3c97f92d5f0a850a0d29c587aa183597d58476a7979602ace3"

  strings:
    $s1  = "var aK = true  , xZav = ZGs[7] + ZGs[9] + ZGs[11];" fullword ascii
    $s2  = "return tAfBqsJ[0] + tAfBqsJ[2] + tAfBqsJ[4] + \".F\" + tAfBqsJ[7] + tAfBqsJ[9] + tAfBqsJ[12] + tAfBqsJ[14];" fullword ascii
    $s3  = "var tAfBqsJ = \"Sc qXeqUwo r icNxKThaZ ipting KKOHclN YvB ile lCJNYJJlTbRrlB System hj iaAeb Obj YPelnF ect raFbwDL\".split(\" " ascii
    $s4  = "xTmBm.open(oFloO,OphEy,false);" fullword ascii
    $s5  = "var ZGs = (\"2.XMLHTTP YDRhDfh rAkFe XML ream St LDqWzXAv AD oHgQoga O pyFs D\").split(\" \");" fullword ascii
    $s6  = "if(w>=R.length) {break;}" fullword ascii
    $s7  = "function cpaa(BfbHj) {" fullword ascii
    $s8  = "function QMIxVYom(sxZ) {" fullword ascii
    $s9  = "function UNCk(lStzN) {" fullword ascii
    $s10 = "if (GrqXW == 1106-906){return true;} else {return false;}" fullword ascii
    $s11 = "function yxnNK(sVpURo) {" fullword ascii
    $s12 = "return ei.ExpandEnvironmentStrings(FaHsv[6]+FaHsv[7]+FaHsv[8]);" fullword ascii
    $s13 = "function nHWj(hhZeS,Wcerl) {" fullword ascii
    $s14 = "return new ActiveXObject(sVpURo);" fullword ascii
    $s15 = "return sxZ.size;" fullword ascii
    $s16 = "if (C >= arBEO.length) {break;}" fullword ascii
    $s17 = "if (BfbHj > 192547-997){return true;} else {return false;}" fullword ascii
    $s18 = "function FZPOmdVbu(uUmsV,YQRZU,QrHvx,kvZn) {" fullword ascii
    $s19 = "function Txqy(xTmBm,OphEy,oFloO) {" fullword ascii
    $s20 = "function pxAfBIF(Mrjj) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}