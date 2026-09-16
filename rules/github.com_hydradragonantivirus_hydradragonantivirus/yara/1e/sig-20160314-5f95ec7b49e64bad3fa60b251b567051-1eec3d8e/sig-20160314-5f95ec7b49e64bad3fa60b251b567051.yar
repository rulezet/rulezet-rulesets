rule sig_20160314_5f95ec7b49e64bad3fa60b251b567051 {
  meta:
    description = "datamaliciousorder - file 20160314_5f95ec7b49e64bad3fa60b251b567051.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b861a381858edd4067db9c1f017492bc2bcfd0591d291adfe65b21bae484049"

  strings:
    $s1  = "var yd = true  , umqs = Rtk[7] + Rtk[9] + Rtk[11];" fullword ascii
    $s2  = "return JFUYgwV[0] + JFUYgwV[2] + JFUYgwV[4] + \".F\" + JFUYgwV[7] + JFUYgwV[9] + JFUYgwV[12] + JFUYgwV[14];" fullword ascii
    $s3  = "var Rtk = (\"2.XMLHTTP UmNiTfn YXpSx XML ream St hjGsVRzn AD hoVvngM O RIDT D\").split(\" \");" fullword ascii
    $s4  = "var JFUYgwV = \"Sc cMwJulh r FZWPHXygq ipting oHJQkMr MOG ile JcDZeZnCEtTGNA System ui ocJuG Obj JrmBuo ect GvqaWhc hDptZ\".spli" ascii
    $s5  = "var JFUYgwV = \"Sc cMwJulh r FZWPHXygq ipting oHJQkMr MOG ile JcDZeZnCEtTGNA System ui ocJuG Obj JrmBuo ect GvqaWhc hDptZ\".spli" ascii
    $s6  = "GrKTV.open(VcZmK,vVqaT,false);" fullword ascii
    $s7  = "return YgCCuUh(AB,iBHiZ[123-117]+iBHiZ[714-707]+iBHiZ[279-271]);" fullword ascii
    $s8  = "if(z>=n.length) {break;}" fullword ascii
    $s9  = "if (CmZlH > 176722-136){return true;} else {return false;}" fullword ascii
    $s10 = "function HDXzUSbhV() {" fullword ascii
    $s11 = "YhE = z; break; " fullword ascii
    $s12 = "return DkPJV;" fullword ascii
    $s13 = "function QOuvg(iAHzJk) {" fullword ascii
    $s14 = "function Qjfr(beWBE,WtFAS) {" fullword ascii
    $s15 = "return josKuZT" fullword ascii
    $s16 = "return gtcl.ExpandEnvironmentStrings(BmkOW);" fullword ascii
    $s17 = "function SDgM(GrKTV,vVqaT,VcZmK) {" fullword ascii
    $s18 = "function UJap(dfEQc) {" fullword ascii
    $s19 = "function KReOEjG(Eqco) {" fullword ascii
    $s20 = "function wbbd(yuzbY) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}