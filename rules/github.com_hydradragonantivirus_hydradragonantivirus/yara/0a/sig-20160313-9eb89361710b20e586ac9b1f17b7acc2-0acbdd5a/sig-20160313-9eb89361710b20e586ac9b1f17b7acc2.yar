rule sig_20160313_9eb89361710b20e586ac9b1f17b7acc2 {
  meta:
    description = "datamaliciousorder - file 20160313_9eb89361710b20e586ac9b1f17b7acc2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01a22f12118c69bdecba862f41e2456e3fe49ac8afe0a555084b142534f65179"

  strings:
    $s1  = "var tG = true  , dXIP = nCd[7] + nCd[9] + nCd[11];" fullword ascii
    $s2  = "return PLcLwKg[0] + PLcLwKg[2] + PLcLwKg[4] + \".F\" + PLcLwKg[7] + PLcLwKg[9] + PLcLwKg[12] + PLcLwKg[14];" fullword ascii
    $s3  = "IMDbR.open(JEGJV,KBibq,false);" fullword ascii
    $s4  = "var PLcLwKg = \"Sc AGSqwch r MQZEUeCnS ipting vwIxUdR yXi ile vcEtYqiGhRzzCZ System Kp JCHtk Obj TzhXPe ect nxMWOHZ\".split(\" " ascii
    $s5  = "var nCd = (\"2.XMLHTTP RHFPinT aOsmk XML ream St MzMsrOow AD YmPCkiR O LvOp D\").split(\" \");" fullword ascii
    $s6  = "function migM(zMyQI) {" fullword ascii
    $s7  = "function PnOWDnwuK() {" fullword ascii
    $s8  = "if (qOtig > 197026-495){return true;} else {return false;}" fullword ascii
    $s9  = "return KDsJ.ExpandEnvironmentStrings(ERGWN);" fullword ascii
    $s10 = "function TQtS(SzjsC) {" fullword ascii
    $s11 = "return qbQx.responseBody;" fullword ascii
    $s12 = "return zMyQI.status;" fullword ascii
    $s13 = "return mKVLYET" fullword ascii
    $s14 = "function KdBw(LDcBI) {" fullword ascii
    $s15 = "function DQgG(IMVSs,BFcyr) {" fullword ascii
    $s16 = "function SUkZZ(LkJxkh) {" fullword ascii
    $s17 = "function JAvS(GWTBB) {" fullword ascii
    $s18 = "function ifSqYaq(KDsJ,ERGWN) {" fullword ascii
    $s19 = "function RCwHtMwfZ(uXMlLMONQgW) {" fullword ascii
    $s20 = "if (GWTBB == 398-198){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}