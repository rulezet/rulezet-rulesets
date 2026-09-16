rule sig_20160312_a0e932ca96156d24c04cb9e7d9f659d1 {
  meta:
    description = "datamaliciousorder - file 20160312_a0e932ca96156d24c04cb9e7d9f659d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28eabe248c25d893d4478087acb6ceb502c5c30ee80e344264db84b22f93609b"

  strings:
    $s1  = "var TH = true  , fUSC = jDV[7] + jDV[9] + jDV[11];" fullword ascii
    $s2  = "return KZypASo[0] + KZypASo[2] + KZypASo[4] + \".F\" + KZypASo[7] + KZypASo[9] + KZypASo[12] + KZypASo[14];" fullword ascii
    $s3  = "var rfs = TuJm(fUSC + \"B.\" + jDV[5]+(335655, jDV[4]));" fullword ascii
    $s4  = "var jDV = (\"2.XMLHTTP mpaDTvU rnBRn XML ream St jYtZuFLL AD yhmpobV O MPPh D\").split(\" \");" fullword ascii
    $s5  = "eSRCs.open(BcXSj,fxBTK,false);" fullword ascii
    $s6  = "return new ActiveXObject(oGWaaV);" fullword ascii
    $s7  = "if (x >= NXYcl.length) {break;}" fullword ascii
    $s8  = "return VuyN.responseBody;" fullword ascii
    $s9  = "function menRF(oGWaaV) {" fullword ascii
    $s10 = "function vqilSplpd(HwpYTYjGvWF) {" fullword ascii
    $s11 = "if(k>=s.length) {break;}" fullword ascii
    $s12 = "function KbAq(QSwdB) {" fullword ascii
    $s13 = "return dVDqCmI(bj,vQfzF[167-161]+vQfzF[937-930]+vQfzF[183-175]);" fullword ascii
    $s14 = "function bikJs(KUtaxV) {" fullword ascii
    $s15 = "return VONVg.status;" fullword ascii
    $s16 = "function dsLe(wUhyZ) {" fullword ascii
    $s17 = "function YrVmbfRw(WhktY,FxlLho) {" fullword ascii
    $s18 = "function krcwULI(VuyN) {" fullword ascii
    $s19 = "function xiPN(npmSi,UarkT) {" fullword ascii
    $s20 = "return OAzgR;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}