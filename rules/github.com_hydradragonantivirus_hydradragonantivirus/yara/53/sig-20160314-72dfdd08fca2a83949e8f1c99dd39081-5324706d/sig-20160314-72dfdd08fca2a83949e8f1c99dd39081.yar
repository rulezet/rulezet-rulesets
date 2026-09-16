rule sig_20160314_72dfdd08fca2a83949e8f1c99dd39081 {
  meta:
    description = "datamaliciousorder - file 20160314_72dfdd08fca2a83949e8f1c99dd39081.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e1dde7407448fe9fa9ab3b110cbb00d23dc48cfeb51bdc184c9fddfd16db9ea"

  strings:
    $s1  = "return qeuzbUF[0] + qeuzbUF[2] + qeuzbUF[4] + \".F\" + qeuzbUF[7] + qeuzbUF[9] + qeuzbUF[12] + qeuzbUF[14];" fullword ascii
    $s2  = "var Fa = true  , MnvE = lDd[7] + lDd[9] + lDd[11];" fullword ascii
    $s3  = "naSoD.open(ApxqK,xdtAd,false);" fullword ascii
    $s4  = "var lDd = (\"2.XMLHTTP BkJKccS OXkZg XML ream St nwQVTEPf AD kLzAYNb O wNqx D\").split(\" \");" fullword ascii
    $s5  = "var qeuzbUF = \"Sc ShdeNdY r AysvTgpNw ipting UHETrIP JBO ile AeiExsVMpBrsIl System KL RDSVA Obj vzTcef ect TgvZAJe sHwcd\".spli" ascii
    $s6  = "var qeuzbUF = \"Sc ShdeNdY r AysvTgpNw ipting UHETrIP JBO ile AeiExsVMpBrsIl System KL RDSVA Obj vzTcef ect TgvZAJe sHwcd\".spli" ascii
    $s7  = "if (B >= NpPpe.length) {break;}" fullword ascii
    $s8  = "function FZdydoFm(NLl) {" fullword ascii
    $s9  = "function DLxY(NpPpe) {" fullword ascii
    $s10 = "function KOLhrrrC() {" fullword ascii
    $s11 = "function yujKkfqYb() {" fullword ascii
    $s12 = "function DWvW(naSoD,xdtAd,ApxqK) {" fullword ascii
    $s13 = "function rBbi(NANMz,RmIfd) {" fullword ascii
    $s14 = "if (ExLhB == 419-219){return true;} else {return false;}" fullword ascii
    $s15 = "function yccY(ExLhB) {" fullword ascii
    $s16 = "function RHJv(xekiW) {" fullword ascii
    $s17 = "if (ukMwe > 163561-663){return true;} else {return false;}" fullword ascii
    $s18 = "function bVuXE(mHxhVf) {" fullword ascii
    $s19 = "function LwhT(ukMwe) {" fullword ascii
    $s20 = "iyq = R; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}