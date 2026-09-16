rule sig_20160405_12d1df613a61f1c2c9d987dd8c35629e {
  meta:
    description = "datamaliciousorder - file 20160405_12d1df613a61f1c2c9d987dd8c35629e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2a0ea8e13de1f2d042622b3661d5fb37ed32464930d694b42ed87142cfbd5ae"

  strings:
    $s1  = "var Lt = true  , XUKd = Ife[7] + Ife[9] + Ife[11];" fullword ascii
    $s2  = "return inyQRYA[0] + inyQRYA[2] + inyQRYA[4] + \".F\" + inyQRYA[7] + inyQRYA[9] + inyQRYA[12] + inyQRYA[14];" fullword ascii
    $s3  = "var Ife = (\"2.XMLHTTP CgdjABb NCYXa XML ream St UhJPqHPf AD fiLsvsJ O ilFi D\").split(\" \");" fullword ascii
    $s4  = "jfWI.open(tSfPB,fzRkG,false);" fullword ascii
    $s5  = "return ibxYlSQ(wt,YvIsW[606-600]+YvIsW[247-240]+YvIsW[367-359]);" fullword ascii
    $s6  = "return grbNo;" fullword ascii
    $s7  = "if(q>=Y.length) {break;}" fullword ascii
    $s8  = "function OSTra(pOgTtH) {" fullword ascii
    $s9  = "return crH.size;" fullword ascii
    $s10 = "function WohpuCYlQ(vSxEc) {" fullword ascii
    $s11 = "function BvJG(yzAIQ,fzRkG,tSfPB) {" fullword ascii
    $s12 = "return DfzJwtX[0];" fullword ascii
    $s13 = "function dhMxucpl(cIlt) {" fullword ascii
    $s14 = "function WdiC(mhlaa) {" fullword ascii
    $s15 = "function IpnFeG(OoEPBCI) {" fullword ascii
    $s16 = "return SaUfx.status;" fullword ascii
    $s17 = "return new ActiveXObject(ueYw);" fullword ascii
    $s18 = "function AjZQcEO(DtpB) {" fullword ascii
    $s19 = "function ibxYlSQ(JtBJ,hdzxf) {" fullword ascii
    $s20 = "if (TYElk > 168374-261){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}