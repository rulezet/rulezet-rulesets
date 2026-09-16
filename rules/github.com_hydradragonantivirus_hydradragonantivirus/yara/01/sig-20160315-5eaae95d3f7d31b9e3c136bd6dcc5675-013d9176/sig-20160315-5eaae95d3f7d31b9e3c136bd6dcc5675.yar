rule sig_20160315_5eaae95d3f7d31b9e3c136bd6dcc5675 {
  meta:
    description = "datamaliciousorder - file 20160315_5eaae95d3f7d31b9e3c136bd6dcc5675.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5663a1576f037d3bc5ba101de3f3fcee40f9881301bc375b6faae0e5c8bdf0f8"

  strings:
    $s1  = "var UO = true  , GeMX = GZJ[7] + GZJ[9] + GZJ[11];" fullword ascii
    $s2  = "return gkjSxnt[0] + gkjSxnt[2] + gkjSxnt[4] + \".F\" + gkjSxnt[7] + gkjSxnt[9] + gkjSxnt[12] + gkjSxnt[14];" fullword ascii
    $s3  = "var GZJ = (\"2.XMLHTTP NVmlMdg oosWc XML ream St QNYknvSw AD uSMyYzh O lBGR D\").split(\" \");" fullword ascii
    $s4  = "var gkjSxnt = TtasY(\"Sc tWwNeGB r JNKxVEtTk ipting jzZnrCN uQx ile IeljQbAVYaQugF System sB lBEMd Obj TxXsno ect jqPVfZT nQajN" ascii
    $s5  = "YCcMW.open(HlZEt,vCqbO,false);" fullword ascii
    $s6  = "var gkjSxnt = TtasY(\"Sc tWwNeGB r JNKxVEtTk ipting jzZnrCN uQx ile IeljQbAVYaQugF System sB lBEMd Obj TxXsno ect jqPVfZT nQajN" ascii
    $s7  = "if(h>=K.length) {break;}" fullword ascii
    $s8  = "return WvYFz;" fullword ascii
    $s9  = "function JihNaiZg(SXm) {" fullword ascii
    $s10 = "function Twwx(OZwzM) {" fullword ascii
    $s11 = "function KUMvPHdzR(CedWB) {" fullword ascii
    $s12 = "function uonb(viECV) {" fullword ascii
    $s13 = "function TtasY(ryt,TVrwL) {" fullword ascii
    $s14 = "return IQVmjFL(YF,LnEJM[838-832]+LnEJM[229-222]+LnEJM[443-435]);" fullword ascii
    $s15 = "function etLBz(nZtapD) {" fullword ascii
    $s16 = "return new ActiveXObject(YQczjf);" fullword ascii
    $s17 = "return ZvJhL.status;" fullword ascii
    $s18 = "return SXm.size;" fullword ascii
    $s19 = "return DfEp.ExpandEnvironmentStrings(RnnKb);" fullword ascii
    $s20 = "return WCOz.responseBody;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}