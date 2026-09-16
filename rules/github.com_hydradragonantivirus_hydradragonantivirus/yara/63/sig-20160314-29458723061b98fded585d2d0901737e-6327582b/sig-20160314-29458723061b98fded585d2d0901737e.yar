rule sig_20160314_29458723061b98fded585d2d0901737e {
  meta:
    description = "datamaliciousorder - file 20160314_29458723061b98fded585d2d0901737e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b135725cf46558ce63d79abb17ff677599bd42837f0faa589471642a5d28057"

  strings:
    $s1  = "var aC = true  , ygea = OFI[7] + OFI[9] + OFI[11];" fullword ascii
    $s2  = "return wtzDUdf[0] + wtzDUdf[2] + wtzDUdf[4] + \".F\" + wtzDUdf[7] + wtzDUdf[9] + wtzDUdf[12] + wtzDUdf[14];" fullword ascii
    $s3  = "NcuYM.open(FlLIu,yrOZn,false);" fullword ascii
    $s4  = "var wtzDUdf = \"Sc iYRGmyK r hitsNLliO ipting eEAfVZM AZm ile NTpbOlrsKEADIv System bx yHLjc Obj nSRVds ect aPZKgmq KtAlz\".spli" ascii
    $s5  = "var wtzDUdf = \"Sc iYRGmyK r hitsNLliO ipting eEAfVZM AZm ile NTpbOlrsKEADIv System bx yHLjc Obj nSRVds ect aPZKgmq KtAlz\".spli" ascii
    $s6  = "var OFI = (\"2.XMLHTTP dMAYCco IOmeI XML ream St BMngvTYs AD vmcDwAd O KVqv D\").split(\" \");" fullword ascii
    $s7  = "return yOSQvv.position=449-449;" fullword ascii
    $s8  = "return evap.responseBody;" fullword ascii
    $s9  = "return FekE.ExpandEnvironmentStrings(AwEMA);" fullword ascii
    $s10 = "return vtOAuou" fullword ascii
    $s11 = "function XmJi(SmDvZ,puoPk) {" fullword ascii
    $s12 = "function XmHE(dSXoK) {" fullword ascii
    $s13 = "function izTS(voGms) {" fullword ascii
    $s14 = "function fHRyNOww() {" fullword ascii
    $s15 = "function TuruSwOdV(NhqSCFjuOEL) {" fullword ascii
    $s16 = "function POLv(LlsWe,SDMAF) {" fullword ascii
    $s17 = "return vnJZqai(Yc,JDlZZ[860-854]+JDlZZ[378-371]+JDlZZ[621-613]);" fullword ascii
    $s18 = "function SqmCh(QEJzya) {" fullword ascii
    $s19 = "return nVQnQ;" fullword ascii
    $s20 = "function xWqy(tXNfd) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}