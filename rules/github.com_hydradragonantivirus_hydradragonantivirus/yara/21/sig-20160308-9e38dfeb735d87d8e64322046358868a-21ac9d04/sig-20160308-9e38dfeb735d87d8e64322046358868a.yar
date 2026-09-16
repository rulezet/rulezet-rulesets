rule sig_20160308_9e38dfeb735d87d8e64322046358868a {
  meta:
    description = "datamaliciousorder - file 20160308_9e38dfeb735d87d8e64322046358868a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85386ba3e6e59fe0c67859907bbca272a1393138fcad3e95bf082b1eee9972e3"

  strings:
    $s1  = "return gHFpLHG[0] + gHFpLHG[2] + gHFpLHG[4] + \".F\" + gHFpLHG[7] + gHFpLHG[9] + gHFpLHG[12] + gHFpLHG[14];" fullword ascii
    $s2  = "var gHFpLHG = \"Sc XuJFTdJ r QwzwVPpHv ipting YqYoTiY lLl ile JUyJnArNIAzXTe System df edmsF Obj XJOvCi ect JekMtVS\".split(\" " ascii
    $s3  = "var vzb = (\"2.XMLHTTP CpNnClx mwLhG XML ream St kdJOepmF AD CpTlEYJ O GYNH D\").split(\" \");" fullword ascii
    $s4  = "DKaOx.open(vYNDD,CbHay,false);" fullword ascii
    $s5  = "return HKdrg;" fullword ascii
    $s6  = "function QtleQZRW(TFy) {" fullword ascii
    $s7  = "function BkDb(DKaOx,CbHay,vYNDD) {" fullword ascii
    $s8  = "function CvMr(tzOKk) {" fullword ascii
    $s9  = "function NdBfSzlIG(NVCQV,cguUK,jWceG,iiIm) {" fullword ascii
    $s10 = "function IQIaCcuMY(NPIczmXOjtO) {" fullword ascii
    $s11 = "function VaQAs(DQBhiJ) {" fullword ascii
    $s12 = "function yBLr(HJfIE) {" fullword ascii
    $s13 = "return new ActiveXObject(DQBhiJ);" fullword ascii
    $s14 = "var cA = true  , Mnjh = vzb[7] + vzb[9] + vzb[11];" fullword ascii
    $s15 = "return TFy.size;" fullword ascii
    $s16 = "function GsJD(sfQGu) {" fullword ascii
    $s17 = "if (((new Date())>0,7626919888)) {" fullword ascii
    $s18 = "if (A >= tzOKk.length) {break;}" fullword ascii
    $s19 = "if(b>=d.length) {break;}" fullword ascii
    $s20 = "return CsCzzAq" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}