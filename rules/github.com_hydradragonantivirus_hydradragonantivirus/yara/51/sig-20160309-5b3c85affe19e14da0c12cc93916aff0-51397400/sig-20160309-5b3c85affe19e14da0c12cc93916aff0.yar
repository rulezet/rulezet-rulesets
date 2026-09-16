rule sig_20160309_5b3c85affe19e14da0c12cc93916aff0 {
  meta:
    description = "datamaliciousorder - file 20160309_5b3c85affe19e14da0c12cc93916aff0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e55418edecf5dbd3ba597b606e5b02682e1d3925d3282bcf4a0bd3f2e7e7ba4"

  strings:
    $s1  = "return qIwtvrg[0] + qIwtvrg[2] + qIwtvrg[4] + \".F\" + qIwtvrg[7] + qIwtvrg[9] + qIwtvrg[12] + qIwtvrg[14];" fullword ascii
    $s2  = "var or = true  , YDHo = PkR[7] + PkR[9] + PkR[11];" fullword ascii
    $s3  = "var qIwtvrg = \"Sc CWySMeX r DaNfimiIV ipting TmLUZgt pmB ile JuHLSDUoewSmkq System DT MfsBg Obj SObWZB ect VUBqjAt\".split(\" " ascii
    $s4  = "VSVPw.open(lpPBa,PLeKV,false);" fullword ascii
    $s5  = "var PkR = (\"2.XMLHTTP yxPASxa aBHrl XML ream St JCcpHKIG AD OOpcJoi O qlyt D\").split(\" \");" fullword ascii
    $s6  = "if(r>=A.length) {break;}" fullword ascii
    $s7  = "function aXkwZyo(qOqp,MrgHu) {" fullword ascii
    $s8  = "function QthiyGK(macM) {" fullword ascii
    $s9  = "if (qZEHD == 747-547){return true;} else {return false;}" fullword ascii
    $s10 = "return aXkwZyo(Wx,kNzaU[460-454]+kNzaU[328-321]+kNzaU[503-495]);" fullword ascii
    $s11 = "function HoWalTAO(tvSXR,iqAnMF) {" fullword ascii
    $s12 = "return macM.responseBody;" fullword ascii
    $s13 = "return qOqp.ExpandEnvironmentStrings(MrgHu);" fullword ascii
    $s14 = "function YVAx(hYNfX) {" fullword ascii
    $s15 = "function xrTpwIJnQ(dWnOb,nmddv,IROjh,NVea) {" fullword ascii
    $s16 = "Vln = r; break; " fullword ascii
    $s17 = "function OsBRqIKPN(UQwRfJQapzv) {" fullword ascii
    $s18 = "function HHIk(EUDgj) {" fullword ascii
    $s19 = "function IXrBVbML() {" fullword ascii
    $s20 = "function JFXi(qZEHD) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}