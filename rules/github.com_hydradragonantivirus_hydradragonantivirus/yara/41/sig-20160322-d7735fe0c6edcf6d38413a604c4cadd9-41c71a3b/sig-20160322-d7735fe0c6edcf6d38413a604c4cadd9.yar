rule sig_20160322_d7735fe0c6edcf6d38413a604c4cadd9 {
  meta:
    description = "datamaliciousorder - file 20160322_d7735fe0c6edcf6d38413a604c4cadd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50ecf4e8dd114e66a050f25bcce976465251ca84baf245374a39661897213fab"

  strings:
    $s1  = "return WScript.CreateObject(XaGED);" fullword ascii
    $s2  = "var bN = true  , czvA = chg[7] + chg[9] + chg[11];" fullword ascii
    $s3  = "var wxe = dAsH(czvA + \"B.\" + chg[5]+(716608, chg[4]));" fullword ascii
    $s4  = "return wnlilnC[0] + wnlilnC[2] + wnlilnC[4] + \".F\" + wnlilnC[7] + wnlilnC[9] + wnlilnC[12] + wnlilnC[14];" fullword ascii
    $s5  = "var tlEQGNUA = dAsH(wmegKZeD[878-877] + wmegKZeD[421-418] + wmegKZeD[958-953] + wmegKZeD[515-509] + wmegKZeD[423-415] + wmegKZeD" ascii
    $s6  = "var tlEQGNUA = dAsH(wmegKZeD[878-877] + wmegKZeD[421-418] + wmegKZeD[958-953] + wmegKZeD[515-509] + wmegKZeD[423-415] + wmegKZeD" ascii
    $s7  = "var wnlilnC = fGXjG(IjiKWpoHTg+\" \"+\"System DX Tmymr Obj EDlWSh ect OTOdVWz tzfLa\", \" \");" fullword ascii
    $s8  = "IcZD.open(HJfpU,JoaGb,false);" fullword ascii
    $s9  = "var chg = (\"2.XMLHTTP pqcMNyk pURTN XML ream St VMFdaeUK AD ZZeZItZ O BvPi D\").split(\" \");" fullword ascii
    $s10 = "ZyI = R; break; " fullword ascii
    $s11 = "return OQd.split(nrZga);" fullword ascii
    $s12 = "return LSNL.ExpandEnvironmentStrings(Axndq);" fullword ascii
    $s13 = "function drzr(ZGKQq) {" fullword ascii
    $s14 = "function fGXjG(OQd,nrZga) {" fullword ascii
    $s15 = "return new ActiveXObject(gZEpcr);" fullword ascii
    $s16 = "function XmYQu(mymNJs) {" fullword ascii
    $s17 = "function ASLZ(kkMuy,pTYzU) {" fullword ascii
    $s18 = "if (KRlQF > 177502-483){return true;} else {return false;}" fullword ascii
    $s19 = "return YDEPZrC(ry,DaCVT[199-193]+DaCVT[436-429]+DaCVT[448-440]);" fullword ascii
    $s20 = "function bDAJ(KRlQF) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}