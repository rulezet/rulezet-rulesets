rule sig_20160411_8ba7dbc730e832e98e78a7fa629e47fb {
  meta:
    description = "datamaliciousorder - file 20160411_8ba7dbc730e832e98e78a7fa629e47fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d350afc961a1614f347fd32dadf2b2f0c49eda98ad4ab32bb6e37c90ae94310"

  strings:
    $s1  = "var Zi = true  , qTXx = sry[7] + sry[9] + sry[11];" fullword ascii
    $s2  = "return rDNHNha[0] + rDNHNha[2] + rDNHNha[4] + \".F\" + rDNHNha[7] + rDNHNha[9] + rDNHNha[12] + rDNHNha[14];" fullword ascii
    $s3  = "qFAH.open(NOTwD,RjokB,false);" fullword ascii
    $s4  = "var sry = (\"2.XMLHTTP jReCglX aJGhx XML ream St BPuvvkUi AD zWewSpR O bqHm D\").split(\" \");" fullword ascii
    $s5  = "if(u>=p.length) {break;}" fullword ascii
    $s6  = "function TccIm(aqMqiYOq,gZGX) {" fullword ascii
    $s7  = "function ksCO(OEQHG) {" fullword ascii
    $s8  = "function pQuYvH(MYCrQSa) {" fullword ascii
    $s9  = "function HdFx(aVDMJ,vdsNr) {" fullword ascii
    $s10 = "return \"mlkDiQfjIUyEiP\";" fullword ascii
    $s11 = "return xeS[AnBz[0]](tlGSI);" fullword ascii
    $s12 = "if (D >= GNAxG.length) {break;}" fullword ascii
    $s13 = "function dZHH(pWyPJ,RjokB,NOTwD) {" fullword ascii
    $s14 = "if (QiiZK > 155998-474){return true;} else {return false;}" fullword ascii
    $s15 = "return WGzNXeR;" fullword ascii
    $s16 = "return EzYfOyN[0];" fullword ascii
    $s17 = "function ZeTDMEg(ruoL) {" fullword ascii
    $s18 = "function HVgrewJm(ErPJ) {" fullword ascii
    $s19 = "function BXiT(QiiZK) {" fullword ascii
    $s20 = "return lIGwlp[RQHL[595-595]]=408-408;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}