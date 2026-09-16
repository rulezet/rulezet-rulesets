rule sig_20160404_973aa27e22c6e5c898e56631da5a48ea {
  meta:
    description = "datamaliciousorder - file 20160404_973aa27e22c6e5c898e56631da5a48ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98b7aa75344ea0f357c988a3bc033e8392c7f716073799671c5ae633947c4e04"

  strings:
    $s1  = "return NjpbuCo[0] + NjpbuCo[2] + NjpbuCo[4] + \".F\" + NjpbuCo[7] + NjpbuCo[9] + NjpbuCo[12] + NjpbuCo[14];" fullword ascii
    $s2  = "var KK = true  , oSFd = eiU[7] + eiU[9] + eiU[11];" fullword ascii
    $s3  = "iURT.open(XtdcI,sTHTu,false);" fullword ascii
    $s4  = "var NjpbuCo = FClth(ltAeAWOOIN+\" \"+\"System EI DwKVQ Obj oHvvZC ect BxdrehF eaKjV\", \" \");" fullword ascii
    $s5  = "var eiU = (\"2.XMLHTTP xQqjyxe ImTDT XML ream St LTigbmgN AD nqAeuxK O yISO D\").split(\" \");" fullword ascii
    $s6  = "function bnuOSFW(mbEv,WjrCX) {" fullword ascii
    $s7  = "function OLaz(pPlVi,sTHTu,XtdcI) {" fullword ascii
    $s8  = "function vtCq(fiUKM) {" fullword ascii
    $s9  = "function XJbrVCLN(Rmk) {" fullword ascii
    $s10 = "return Rmk.size;" fullword ascii
    $s11 = "function TgCDz(FLBCQB) {" fullword ascii
    $s12 = "function trvy(DyvAH) {" fullword ascii
    $s13 = "return eKQz[wixuBC[0]];" fullword ascii
    $s14 = "function xJVKKda(eKQz) {" fullword ascii
    $s15 = "function GccfE(oomhrE) {" fullword ascii
    $s16 = "function OlFgGi(sqrxGbV) {" fullword ascii
    $s17 = "function yZOog(liIEXPeq,KKQW) {" fullword ascii
    $s18 = "function YJtj(tCzmD) {" fullword ascii
    $s19 = "var LTeKSVq = \"rktzjw*SuO*pt.S\"+\"hell*MrSJUly*Scri*\";" fullword ascii
    $s20 = "function bUJZnU(anyT,bOMdrx) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}