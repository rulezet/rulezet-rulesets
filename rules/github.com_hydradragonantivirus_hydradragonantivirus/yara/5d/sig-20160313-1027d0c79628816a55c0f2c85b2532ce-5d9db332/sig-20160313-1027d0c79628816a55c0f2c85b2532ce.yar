rule sig_20160313_1027d0c79628816a55c0f2c85b2532ce {
  meta:
    description = "datamaliciousorder - file 20160313_1027d0c79628816a55c0f2c85b2532ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc407c704a10c685fce719a6f8d5b7f5068a64a568b3ffd9662b1041f49dd8cc"

  strings:
    $s1  = "return kPTspfW[0] + kPTspfW[2] + kPTspfW[4] + \".F\" + kPTspfW[7] + kPTspfW[9] + kPTspfW[12] + kPTspfW[14];" fullword ascii
    $s2  = "var Td = true  , tkOE = cBu[7] + cBu[9] + cBu[11];" fullword ascii
    $s3  = "var cBu = (\"2.XMLHTTP rRTSdnL gtwJF XML ream St lpQTwlbW AD vDmsFKG O wvdt D\").split(\" \");" fullword ascii
    $s4  = "uqwxF.open(TADGX,OXoUA,false);" fullword ascii
    $s5  = "var kPTspfW = \"Sc WpJUYcl r OGSkDuqSV ipting DmNbCNl TlB ile tHKHbQkLXYYTNI System wP dNJTZ Obj pIwPuS ect fMqbtJb\".split(\" " ascii
    $s6  = "function SerN(oWeDO) {" fullword ascii
    $s7  = "return new ActiveXObject(GRsqCN);" fullword ascii
    $s8  = "function ldoz(uqwxF,OXoUA,TADGX) {" fullword ascii
    $s9  = "return nvWTQAg(ra,kxEPo[789-783]+kxEPo[653-646]+kxEPo[776-768]);" fullword ascii
    $s10 = "function RksIMweJ(IOt) {" fullword ascii
    $s11 = "return udFjA.status;" fullword ascii
    $s12 = "function HFjrj(BOMCin) {" fullword ascii
    $s13 = "if (Z >= xHmWa.length) {break;}" fullword ascii
    $s14 = "function vWCOzTDt() {" fullword ascii
    $s15 = "function Ljsm(OKnIG,rrqQz) {" fullword ascii
    $s16 = "function hugF(jHuXQ) {" fullword ascii
    $s17 = "function WnyKD(GRsqCN) {" fullword ascii
    $s18 = "function lFkw(udFjA) {" fullword ascii
    $s19 = "return IOt.size;" fullword ascii
    $s20 = "return BOMCin.position=728-728;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}