rule sig_20160308_72a9196db5e5083a9723ef9b0e4d852f {
  meta:
    description = "datamaliciousorder - file 20160308_72a9196db5e5083a9723ef9b0e4d852f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45b8336f636a840da151bc5ed7e2b24e9d1111b88899908e2a3e0199287869ec"

  strings:
    $s1  = "return ZlHjwCN[0] + ZlHjwCN[2] + ZlHjwCN[4] + \".F\" + ZlHjwCN[7] + ZlHjwCN[9] + ZlHjwCN[12] + ZlHjwCN[14];" fullword ascii
    $s2  = "var tq = true  , vFua = nNt[7] + nNt[9] + nNt[11];" fullword ascii
    $s3  = "svSfV.open(MXsSt,IWWdR,false);" fullword ascii
    $s4  = "var ZlHjwCN = \"Sc aHoHBcl r feyqsckAr ipting bYVDcgB yCZ ile UeBCTmVmzYRKOe System AQ WXDUy Obj dSOIRU ect giVAXZs\".split(\" " ascii
    $s5  = "var nNt = (\"2.XMLHTTP NzdscVN NqjTF XML ream St ucHfNORU AD UepNabj O ZFHx D\").split(\" \");" fullword ascii
    $s6  = "QsF = q; break; " fullword ascii
    $s7  = "return new ActiveXObject(WhRCiA);" fullword ascii
    $s8  = "function QGjY(nDuwi) {" fullword ascii
    $s9  = "function Czkx(mDjXs) {" fullword ascii
    $s10 = "function DrvPgqQ(Lzhz) {" fullword ascii
    $s11 = "return SgBwF;" fullword ascii
    $s12 = "function tlZd(xLrAn) {" fullword ascii
    $s13 = "function ObAK(SLiuq) {" fullword ascii
    $s14 = "function CSoC(QYuwg) {" fullword ascii
    $s15 = "function UdMb(QXiVr) {" fullword ascii
    $s16 = "function uOXdqbFG(Mdj) {" fullword ascii
    $s17 = "function rymb(jEQTZ) {" fullword ascii
    $s18 = "function GvQO(QnChv,zhLsT) {" fullword ascii
    $s19 = "if (nDuwi == 645-445){return true;} else {return false;}" fullword ascii
    $s20 = "return Lzhz.responseBody;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}