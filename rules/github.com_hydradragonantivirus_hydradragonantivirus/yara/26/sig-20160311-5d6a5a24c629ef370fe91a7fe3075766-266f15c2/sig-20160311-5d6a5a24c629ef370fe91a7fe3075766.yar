rule sig_20160311_5d6a5a24c629ef370fe91a7fe3075766 {
  meta:
    description = "datamaliciousorder - file 20160311_5d6a5a24c629ef370fe91a7fe3075766.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e6f55239ce3e71cdee215dc7a000744af4fa007d50599691bb54ef6489f962d"

  strings:
    $s1  = "var YR = true  , RjhD = QDD[7] + QDD[9] + QDD[11];" fullword ascii
    $s2  = "return zNtgBFy[0] + zNtgBFy[2] + zNtgBFy[4] + \".F\" + zNtgBFy[7] + zNtgBFy[9] + zNtgBFy[12] + zNtgBFy[14];" fullword ascii
    $s3  = "var QDD = (\"2.XMLHTTP aUSLKjA QcgsA XML ream St pqaERfCZ AD AjOUTnK O Fvts D\").split(\" \");" fullword ascii
    $s4  = "dZBEp.open(TDfRq,GFrZg,false);" fullword ascii
    $s5  = "if (culaW == 303-103){return true;} else {return false;}" fullword ascii
    $s6  = "return RSMki;" fullword ascii
    $s7  = "function sYqK(YqVyH,yJtIV) {" fullword ascii
    $s8  = "if (x >= FuiOA.length) {break;}" fullword ascii
    $s9  = "function OfsH(dgOja) {" fullword ascii
    $s10 = "function KNDOW(JXCZbi) {" fullword ascii
    $s11 = "if (OIuND > 130827-822){return true;} else {return false;}" fullword ascii
    $s12 = "function VUjQtkPB(jNI) {" fullword ascii
    $s13 = "function SdJY(Izgly) {" fullword ascii
    $s14 = "return kyfXzMn(fx,yUlMt[1005-999]+yUlMt[665-658]+yUlMt[604-596]);" fullword ascii
    $s15 = "function wXePbBr(LAWU) {" fullword ascii
    $s16 = "function qKpN(OIuND) {" fullword ascii
    $s17 = "function VwLNXBEhR(wDPEoqwUaes) {" fullword ascii
    $s18 = "function ZIidPXEB() {" fullword ascii
    $s19 = "function dVvQi(mDriTW) {" fullword ascii
    $s20 = "function uKcy(FuiOA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}