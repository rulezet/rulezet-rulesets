rule sig_20160314_de037026170b4ba6d3cfcc559ee2a223 {
  meta:
    description = "datamaliciousorder - file 20160314_de037026170b4ba6d3cfcc559ee2a223.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a743bd5c604c7925e24336a99e7283ed07a024de7fc9d04d2c1b672e866c8bf5"

  strings:
    $s1  = "return nhtoIiG[0] + nhtoIiG[2] + nhtoIiG[4] + \".F\" + nhtoIiG[7] + nhtoIiG[9] + nhtoIiG[12] + nhtoIiG[14];" fullword ascii
    $s2  = "var Qv = true  , pQHw = FEy[7] + FEy[9] + FEy[11];" fullword ascii
    $s3  = "var nhtoIiG = \"Sc gewCyiJ r NzkMGxiXL ipting UVQSdZm nje ile MbhUysfDJjKmCP System cW azBEG Obj fxeVjw ect imtTqQC emQEI\".spli" ascii
    $s4  = "var nhtoIiG = \"Sc gewCyiJ r NzkMGxiXL ipting UVQSdZm nje ile MbhUysfDJjKmCP System cW azBEG Obj fxeVjw ect imtTqQC emQEI\".spli" ascii
    $s5  = "TtnRS.open(GDtFO,VMHor,false);" fullword ascii
    $s6  = "var FEy = (\"2.XMLHTTP QMWFKba pEgnn XML ream St OLyTmsvu AD hKvewEk O WfDt D\").split(\" \");" fullword ascii
    $s7  = "if (JMrJp > 182614-565){return true;} else {return false;}" fullword ascii
    $s8  = "function gOAC(ukwlu,ZlgXX) {" fullword ascii
    $s9  = "function xBVUlkAN() {" fullword ascii
    $s10 = "if (bsIGZ == 745-545){return true;} else {return false;}" fullword ascii
    $s11 = "function NXbxbZD(bQhZ,TIuVZ) {" fullword ascii
    $s12 = "return NXbxbZD(Jq,NnIJu[861-855]+NnIJu[990-983]+NnIJu[709-701]);" fullword ascii
    $s13 = "function UBeq(JMrJp) {" fullword ascii
    $s14 = "function FzGKZjbKl() {" fullword ascii
    $s15 = "return zrGFC.status;" fullword ascii
    $s16 = "function SMXa(zrGFC) {" fullword ascii
    $s17 = "if (n >= bWMMk.length) {break;}" fullword ascii
    $s18 = "if(B>=A.length) {break;}" fullword ascii
    $s19 = "lGI = B; break; " fullword ascii
    $s20 = "function uwDpv(sqtYRk) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}