rule sig_20160310_e0d92fda6dd9b8174cb499afd1d8316b {
  meta:
    description = "datamaliciousorder - file 20160310_e0d92fda6dd9b8174cb499afd1d8316b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e06f2993ca7b7c65c2b89686009f114d2569c33aaf2c2b380788dda298223fcb"

  strings:
    $s1  = "return AfPTcte[0] + AfPTcte[2] + AfPTcte[4] + \".F\" + AfPTcte[7] + AfPTcte[9] + AfPTcte[12] + AfPTcte[14];" fullword ascii
    $s2  = "var oy = true  , bSFU = Txf[7] + Txf[9] + Txf[11];" fullword ascii
    $s3  = "TYanS.open(XqHWP,QzXCr,false);" fullword ascii
    $s4  = "var Txf = (\"2.XMLHTTP cNTZxBM OdsKq XML ream St bkjKnwAy AD rdEuVYd O nSqD D\").split(\" \");" fullword ascii
    $s5  = "var AfPTcte = \"Sc nlcMCIH r CXJIWwGNu ipting qvhNBLS heM ile cKJIbdPkAoHeGp System pR mPXXg Obj nfEqmu ect bJSaWze\".split(\" " ascii
    $s6  = "function GcqAPnvi(Lhmld,GxLEWN) {" fullword ascii
    $s7  = "return MXZzD.status;" fullword ascii
    $s8  = "if(t>=n.length) {break;}" fullword ascii
    $s9  = "function eJNV(NnrMb,FnKhp) {" fullword ascii
    $s10 = "return TlWjLnJ" fullword ascii
    $s11 = "return nps.size;" fullword ascii
    $s12 = "function gVtXJyF(IJkS) {" fullword ascii
    $s13 = "function knwM(TYanS,QzXCr,XqHWP) {" fullword ascii
    $s14 = "function VePyjVsX() {" fullword ascii
    $s15 = "function rrHx(AukMc) {" fullword ascii
    $s16 = "return POPg.ExpandEnvironmentStrings(JOvuw);" fullword ascii
    $s17 = "return new ActiveXObject(GODfoJ);" fullword ascii
    $s18 = "function CyIC(NiFLq) {" fullword ascii
    $s19 = "function tbjm(iaMYN) {" fullword ascii
    $s20 = "return cBYFF;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}