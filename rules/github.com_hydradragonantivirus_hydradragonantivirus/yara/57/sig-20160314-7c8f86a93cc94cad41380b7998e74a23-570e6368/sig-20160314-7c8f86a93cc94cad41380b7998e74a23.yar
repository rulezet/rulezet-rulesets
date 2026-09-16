rule sig_20160314_7c8f86a93cc94cad41380b7998e74a23 {
  meta:
    description = "datamaliciousorder - file 20160314_7c8f86a93cc94cad41380b7998e74a23.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84d3882be04cd3ac81ebe5d0e8fc13fc36cd3bb09bd446eb3fcf25124c72ef3a"

  strings:
    $s1  = "return rXhGYjF[0] + rXhGYjF[2] + rXhGYjF[4] + \".F\" + rXhGYjF[7] + rXhGYjF[9] + rXhGYjF[12] + rXhGYjF[14];" fullword ascii
    $s2  = "var jt = true  , GLDc = WQS[7] + WQS[9] + WQS[11];" fullword ascii
    $s3  = "var tAWAvWWc = SIEr(kqBrLkmR[686-685] + kqBrLkmR[616-613] + kqBrLkmR[844-839] + kqBrLkmR[920-914] + kqBrLkmR[535-527] + kqBrLkmR" ascii
    $s4  = "var wtF = SIEr(GLDc + \"B.\" + WQS[5]+(221844, WQS[4]));" fullword ascii
    $s5  = "var tAWAvWWc = SIEr(kqBrLkmR[686-685] + kqBrLkmR[616-613] + kqBrLkmR[844-839] + kqBrLkmR[920-914] + kqBrLkmR[535-527] + kqBrLkmR" ascii
    $s6  = "var WQS = (\"2.XMLHTTP XSxcqoX mdQAw XML ream St RlsfTMgN AD cuJzFzn O MrCm D\").split(\" \");" fullword ascii
    $s7  = "var rXhGYjF = \"Sc fpfeFjH r zBsEXxsEg ipting VjnRfsE Xqu ile lHphRvrAXNkMse System gT FmuMF Obj UkIXQm ect SNmCcXt dKDwG\".spli" ascii
    $s8  = "sryra.open(OcySh,qpHxQ,false);" fullword ascii
    $s9  = "var rXhGYjF = \"Sc fpfeFjH r zBsEXxsEg ipting VjnRfsE Xqu ile lHphRvrAXNkMse System gT FmuMF Obj UkIXQm ect SNmCcXt dKDwG\".spli" ascii
    $s10 = "function rYYOJfLXz() {" fullword ascii
    $s11 = "var Pr = SIEr(\"MS\"+WQS[3]+(199782, WQS[0]));" fullword ascii
    $s12 = "return tmdpI;" fullword ascii
    $s13 = "return tQoB.responseBody;" fullword ascii
    $s14 = "function FQCz(aPwQz) {" fullword ascii
    $s15 = "function rzBV(TqkAw) {" fullword ascii
    $s16 = "function XwYsSWao() {" fullword ascii
    $s17 = "function voTe(dlzKB) {" fullword ascii
    $s18 = "return new ActiveXObject(KZaQPu);" fullword ascii
    $s19 = "function tJdKd(Khkfcn) {" fullword ascii
    $s20 = "if (dlzKB == 644-444){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}