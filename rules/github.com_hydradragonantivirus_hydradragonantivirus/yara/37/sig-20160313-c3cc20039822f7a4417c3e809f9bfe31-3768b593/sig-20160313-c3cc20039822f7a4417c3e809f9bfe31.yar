rule sig_20160313_c3cc20039822f7a4417c3e809f9bfe31 {
  meta:
    description = "datamaliciousorder - file 20160313_c3cc20039822f7a4417c3e809f9bfe31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebeaeadf84fe0034f636ac099ede257280813dbd0178aecc4578527e80af78ed"

  strings:
    $s1  = "var QA = true  , BARz = xDR[7] + xDR[9] + xDR[11];" fullword ascii
    $s2  = "return jPgBGsT[0] + jPgBGsT[2] + jPgBGsT[4] + \".F\" + jPgBGsT[7] + jPgBGsT[9] + jPgBGsT[12] + jPgBGsT[14];" fullword ascii
    $s3  = "var xDR = (\"2.XMLHTTP YoqgeQl tHKcD XML ream St BcbMfGxU AD xLyDYjZ O Fhsb D\").split(\" \");" fullword ascii
    $s4  = "oVocI.open(Ihdmq,kyuyh,false);" fullword ascii
    $s5  = "var jPgBGsT = \"Sc MMJVGNO r EVgRjzBrA ipting tuNjSWk eZk ile QxSbJUoIpyeliS System hH ngVjs Obj MSsSyv ect aUYVXBy\".split(\" " ascii
    $s6  = "function esSg(NPKQD,DOixw) {" fullword ascii
    $s7  = "return rNRbo;" fullword ascii
    $s8  = "function OKxM(zpMkJ) {" fullword ascii
    $s9  = "return new ActiveXObject(pXnrlF);" fullword ascii
    $s10 = "if (aJoUp == 943-743){return true;} else {return false;}" fullword ascii
    $s11 = "return ApTSLfb(oi,MldGp[810-804]+MldGp[385-378]+MldGp[995-987]);" fullword ascii
    $s12 = "function RwjD(oVocI,kyuyh,Ihdmq) {" fullword ascii
    $s13 = "return rRUd.responseBody;" fullword ascii
    $s14 = "function AuhF(bSOfy) {" fullword ascii
    $s15 = "function WKNq(DuCHV) {" fullword ascii
    $s16 = "function YPcYh(rJniMX) {" fullword ascii
    $s17 = "return DuCHV.status;" fullword ascii
    $s18 = "function cZvX(vyymw) {" fullword ascii
    $s19 = "if(y>=V.length) {break;}" fullword ascii
    $s20 = "return JRigiNU" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}