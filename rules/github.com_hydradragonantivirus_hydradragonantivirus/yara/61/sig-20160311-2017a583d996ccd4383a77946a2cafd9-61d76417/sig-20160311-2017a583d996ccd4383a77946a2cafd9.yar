rule sig_20160311_2017a583d996ccd4383a77946a2cafd9 {
  meta:
    description = "datamaliciousorder - file 20160311_2017a583d996ccd4383a77946a2cafd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63799995dd749f1f6e3eddc7ddc0a5a7b63f9d5d5264856507ed5a0e34d81c14"

  strings:
    $s1  = "return IjHhpGN[0] + IjHhpGN[2] + IjHhpGN[4] + \".F\" + IjHhpGN[7] + IjHhpGN[9] + IjHhpGN[12] + IjHhpGN[14];" fullword ascii
    $s2  = "var SP = true  , ihuq = CjM[7] + CjM[9] + CjM[11];" fullword ascii
    $s3  = "var CjM = (\"2.XMLHTTP FlMWaSw GZsxz XML ream St WWvNvuZm AD doBFdSA O jCQZ D\").split(\" \");" fullword ascii
    $s4  = "var IjHhpGN = \"Sc schDhJU r eazlhWbrT ipting wdnNlWz Gzt ile NrBuEITqqVTFAe System cS CjHkX Obj liQETj ect GkclSmt\".split(\" " ascii
    $s5  = "cFJeL.open(AQcFF,tfzol,false);" fullword ascii
    $s6  = "if(s>=k.length) {break;}" fullword ascii
    $s7  = "return EsjbVGN(et,QjfSE[958-952]+QjfSE[637-630]+QjfSE[460-452]);" fullword ascii
    $s8  = "return yJFc.responseBody;" fullword ascii
    $s9  = "return jVN.size;" fullword ascii
    $s10 = "function MNlkTrVKZ(chvGydvRZvC) {" fullword ascii
    $s11 = "if (PHnDf > 135910-688){return true;} else {return false;}" fullword ascii
    $s12 = "return ouGhvex" fullword ascii
    $s13 = "function hJzdedHOc() {" fullword ascii
    $s14 = "function Ffwy(cFJeL,tfzol,AQcFF) {" fullword ascii
    $s15 = "function gmnHX(BZxSeq) {" fullword ascii
    $s16 = "function wgHIm(dWGpKY) {" fullword ascii
    $s17 = "function utCL(PdnCO,vpifp) {" fullword ascii
    $s18 = "function mvBU(yZtSJ) {" fullword ascii
    $s19 = "Foj = s; break; " fullword ascii
    $s20 = "function jHKPlBgH(hglKM,ISurWd) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}