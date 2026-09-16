rule sig_20160404_0e15a63b116719b1f378865f3ba07c15 {
  meta:
    description = "datamaliciousorder - file 20160404_0e15a63b116719b1f378865f3ba07c15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c25cbe5d71812a1f926f83b93654c29b9ab570a899ca26a96899029d51b4bc83"

  strings:
    $s1  = "return sMvnQpH[0] + sMvnQpH[2] + sMvnQpH[4] + \".F\" + sMvnQpH[7] + sMvnQpH[9] + sMvnQpH[12] + sMvnQpH[14];" fullword ascii
    $s2  = "var DA = true  , nFoc = Jvn[7] + Jvn[9] + Jvn[11];" fullword ascii
    $s3  = "rKso.open(vQbag,jpPkB,false);" fullword ascii
    $s4  = "var Jvn = (\"2.XMLHTTP iroOJRf aYKfG XML ream St gfkgiFQp AD gGpapev O NbSI D\").split(\" \");" fullword ascii
    $s5  = "var sMvnQpH = TvZOP(UTqoauTQmo+\" \"+\"System fn BLnPP Obj bWnkVB ect ZBiOayS HFIlj\", \" \");" fullword ascii
    $s6  = "function GJvctVo(jpDm,kkPih) {" fullword ascii
    $s7  = "return maBsT;" fullword ascii
    $s8  = "function IkPA(TFjYj) {" fullword ascii
    $s9  = "function DUGz(KdbVM) {" fullword ascii
    $s10 = "function AFwJR(TjIoPl) {" fullword ascii
    $s11 = "JUf = S; break; " fullword ascii
    $s12 = "function ipTdlvUd(eJJG) {" fullword ascii
    $s13 = "return PPf.size;" fullword ascii
    $s14 = "function XYCD(TIsRe) {" fullword ascii
    $s15 = "function oQBALNwLx(PJYwWXtFgCr) {" fullword ascii
    $s16 = "function tXQD(rgPjD) {" fullword ascii
    $s17 = "return \"NAfmAVOtXhGeis\";" fullword ascii
    $s18 = "function DQbhdwIct(zylzQ) {" fullword ascii
    $s19 = "function hlKt(Fqnwz,FZqvi) {" fullword ascii
    $s20 = "function habXm(PNQTxA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}