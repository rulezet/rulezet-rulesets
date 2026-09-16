rule sig_20160309_669aa4a025848621b52e920531b98fd9 {
  meta:
    description = "datamaliciousorder - file 20160309_669aa4a025848621b52e920531b98fd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12ed2c62ff25bddcbe7dc7e275014b6fa2b9aed1544857e5adc65c2479f0f159"

  strings:
    $s1  = "var JH = true  , sSvs = swW[7] + swW[9] + swW[11];" fullword ascii
    $s2  = "return NrlDApF[0] + NrlDApF[2] + NrlDApF[4] + \".F\" + NrlDApF[7] + NrlDApF[9] + NrlDApF[12] + NrlDApF[14];" fullword ascii
    $s3  = "var swW = (\"2.XMLHTTP ELAOZtv eUowk XML ream St wWWxHGtv AD DsJLzqQ O IJJO D\").split(\" \");" fullword ascii
    $s4  = "var NrlDApF = \"Sc bKTvdqq r IwzleyvIf ipting wgIFsUR glW ile QDafBOjfKQXlUr System gp niUts Obj cdiskw ect WSbGmAl\".split(\" " ascii
    $s5  = "ebdgH.open(LHKGy,ePViQ,false);" fullword ascii
    $s6  = "if(m>=c.length) {break;}" fullword ascii
    $s7  = "if (LBFlk == 552-352){return true;} else {return false;}" fullword ascii
    $s8  = "if (lCfsI > 153476-969){return true;} else {return false;}" fullword ascii
    $s9  = "function AajGTEf(RCPm) {" fullword ascii
    $s10 = "return knl.size;" fullword ascii
    $s11 = "return zrrLhzl(Ro,rrsge[705-699]+rrsge[174-167]+rrsge[797-789]);" fullword ascii
    $s12 = "function RdMz(YGZRh,iFjYQ) {" fullword ascii
    $s13 = "function CeKH(xGBvb) {" fullword ascii
    $s14 = "function qJho(qGzVq) {" fullword ascii
    $s15 = "function PlwZ(hyRnl) {" fullword ascii
    $s16 = "function zwcg(OVvLb) {" fullword ascii
    $s17 = "if (P >= OVvLb.length) {break;}" fullword ascii
    $s18 = "return UDVhaln" fullword ascii
    $s19 = "function DYgLWpIA() {" fullword ascii
    $s20 = "function vpBGXCuiO(XJCSm,DySKg,DRsLH,XUCc) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}