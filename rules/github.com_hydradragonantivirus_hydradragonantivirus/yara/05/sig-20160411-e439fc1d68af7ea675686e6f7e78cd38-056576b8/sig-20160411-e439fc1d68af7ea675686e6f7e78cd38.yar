rule sig_20160411_e439fc1d68af7ea675686e6f7e78cd38 {
  meta:
    description = "datamaliciousorder - file 20160411_e439fc1d68af7ea675686e6f7e78cd38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "070be5d941012b9c07cc7483a7fa8c02e40230b5d8a7a687b0a1aa7e7d4f0ced"

  strings:
    $s1  = "var uQ = true  , EMwP = OEs[7] + OEs[9] + OEs[11];" fullword ascii
    $s2  = "return dtqisyO[0] + dtqisyO[2] + dtqisyO[4] + \".F\" + dtqisyO[7] + dtqisyO[9] + dtqisyO[12] + dtqisyO[14];" fullword ascii
    $s3  = "var OEs = (\"2.XMLHTTP BGBKRas QqviQ XML ream St EjKGOYFf AD BHrrTSX O pHfP D\").split(\" \");" fullword ascii
    $s4  = "bkcW.open(WnkCN,JFwoN,false);" fullword ascii
    $s5  = "function NUJD(fPAjL) {" fullword ascii
    $s6  = "function OyPT(rYgjJ) {" fullword ascii
    $s7  = "return wDDF[PPVlcIR[0]+PPVlcIR[1]];" fullword ascii
    $s8  = "function vzHCLiicM(kjIWKkLZVfI) {" fullword ascii
    $s9  = "function EkqzK(rvh,SqPcR) {" fullword ascii
    $s10 = "return rvh[LpCx[0]](SqPcR);" fullword ascii
    $s11 = "function uHufcVlWY(CMowz) {" fullword ascii
    $s12 = "function NWtoeNfI(Kpg) {" fullword ascii
    $s13 = "return ydgdzjz(MI,qzfBLh+QrZxs[283-275]);" fullword ascii
    $s14 = "return UjXkM.status;" fullword ascii
    $s15 = "return new ActiveXObject(KkAA);" fullword ascii
    $s16 = "function SLEk(qxVyX) {" fullword ascii
    $s17 = "if (qxVyX > 186551-987){return true;} else {return false;}" fullword ascii
    $s18 = "return uBNns;" fullword ascii
    $s19 = "function QwRX(feuJN) {" fullword ascii
    $s20 = "function kfqx(xiAcy) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}