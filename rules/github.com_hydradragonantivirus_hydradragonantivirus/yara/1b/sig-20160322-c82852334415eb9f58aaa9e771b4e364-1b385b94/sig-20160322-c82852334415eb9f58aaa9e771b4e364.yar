rule sig_20160322_c82852334415eb9f58aaa9e771b4e364 {
  meta:
    description = "datamaliciousorder - file 20160322_c82852334415eb9f58aaa9e771b4e364.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "883215652a566f4ee956b62745e4fe2ac379885aeb201cbab7a06171d95a7457"

  strings:
    $s1  = "return WScript.CreateObject(mLkkT);" fullword ascii
    $s2  = "return PwamRqg[0] + PwamRqg[2] + PwamRqg[4] + \".F\" + PwamRqg[7] + PwamRqg[9] + PwamRqg[12] + PwamRqg[14];" fullword ascii
    $s3  = "var Se = true  , fELC = TfK[7] + TfK[9] + TfK[11];" fullword ascii
    $s4  = "var PwamRqg = YSvuj(gAZcrHlkKE+\" \"+\"System cN hoNeh Obj tjCWtx ect VbLCVgr toclf\", \" \");" fullword ascii
    $s5  = "var TfK = (\"2.XMLHTTP CysqDeu lPDjP XML ream St xEAFJYCK AD ZgMGbyo O seqg D\").split(\" \");" fullword ascii
    $s6  = "ryTq.open(rxApa,bORmr,false);" fullword ascii
    $s7  = "if(y>=J.length) {break;}" fullword ascii
    $s8  = "function xeMT(jKLWe,bORmr,rxApa) {" fullword ascii
    $s9  = "return RcVv[sxbAJU[0]];" fullword ascii
    $s10 = "return fZC.size;" fullword ascii
    $s11 = "function rNzG(UILIc) {" fullword ascii
    $s12 = "function VCDaUks(kyDr,duhed) {" fullword ascii
    $s13 = "function Vemj(EhphP) {" fullword ascii
    $s14 = "return kyDr.ExpandEnvironmentStrings(duhed);" fullword ascii
    $s15 = "function IKQt(LWXCI,oSIGj) {" fullword ascii
    $s16 = "function tCFxkNS(RcVv) {" fullword ascii
    $s17 = "function FkCVCcVd(fZC) {" fullword ascii
    $s18 = "function GdVt(QswBM) {" fullword ascii
    $s19 = "return QiCFZ;" fullword ascii
    $s20 = "function MpUj(gfqdW,TYDMP) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}