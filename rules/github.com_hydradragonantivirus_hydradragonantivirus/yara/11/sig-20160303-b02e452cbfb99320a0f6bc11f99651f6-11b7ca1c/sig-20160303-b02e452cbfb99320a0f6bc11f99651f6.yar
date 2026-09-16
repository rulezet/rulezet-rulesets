rule sig_20160303_b02e452cbfb99320a0f6bc11f99651f6 {
  meta:
    description = "datamaliciousorder - file 20160303_b02e452cbfb99320a0f6bc11f99651f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ca602ededafe76f6b7eecc3f6517ac1113fd5eb4ebf40ec0af9e84dd03e6c03"

  strings:
    $s1  = "var TCYXr = \"urAKeZ cuR pt.Shell wrOJyvP Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var qIy = (tvj + \"TTP\" + \" ZZgoUVq jvYQj XML ream St wmFagLQH AD ucXsbdj OD\").split(\" \");" fullword ascii
    $s3  = "return PWjoVGK[0] + PWjoVGK[2] + PWjoVGK[4] + \".F\" + PWjoVGK[7] + PWjoVGK[9] + PWjoVGK[12] + PWjoVGK[14];" fullword ascii
    $s4  = "var Xq = true  , jwBV = qIy[7] + \"\" + qIy[9];" fullword ascii
    $s5  = "var PWjoVGK = \"Sc CMXEvBR r bsnNwUPnv ipting PFCiEUG eFe ile JHDVzAfYYPFBVl System qX VoDHw Obj dLatbF ect iHlGhjd\".split(\" " ascii
    $s6  = "Lzwsh.open(nkRWn,RMpVF,false);" fullword ascii
    $s7  = "if (((new Date())>0,7898416888)) {" fullword ascii
    $s8  = "function sdPlTpiU() {" fullword ascii
    $s9  = "return dNwfB.status;" fullword ascii
    $s10 = "return RpMb.responseBody;" fullword ascii
    $s11 = "function QxFE(dNwfB) {" fullword ascii
    $s12 = "function mvoi(OyttA) {" fullword ascii
    $s13 = "function CedNgOP(UnlB) {" fullword ascii
    $s14 = "return mS.ExpandEnvironmentStrings(TCYXr[6]);" fullword ascii
    $s15 = "function gYGt(Lzwsh,RMpVF,nkRWn) {" fullword ascii
    $s16 = "zoqu(uqe); uqe.type = 1; vhNF(uqe,QwfqluW(FW)); if (rEnT(uqe.size))  {" fullword ascii
    $s17 = "return new ActiveXObject(XWvzMY);" fullword ascii
    $s18 = "return eKVvWKK" fullword ascii
    $s19 = "function IaTF(HzxuK) {" fullword ascii
    $s20 = "if(G>=W.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}