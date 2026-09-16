rule sig_20160314_c484925ddfe00e35f9eba77ccb2a3d10 {
  meta:
    description = "datamaliciousorder - file 20160314_c484925ddfe00e35f9eba77ccb2a3d10.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5bc6295f704b95f03e602d1a3dd1b52cf60edeb026032cc605cfc8acf88e23e"

  strings:
    $s1  = "var ND = true  , Gfdj = HsK[7] + HsK[9] + HsK[11];" fullword ascii
    $s2  = "return LHdmXQP[0] + LHdmXQP[2] + LHdmXQP[4] + \".F\" + LHdmXQP[7] + LHdmXQP[9] + LHdmXQP[12] + LHdmXQP[14];" fullword ascii
    $s3  = "var LHdmXQP = \"Sc zAKMRXa r vpnAZtROW ipting wKXBczC Cut ile jmmAZXoGmUSHwv System yG OgnZr Obj wSFqHN ect mtvJpex Ujmzi\".spli" ascii
    $s4  = "var LHdmXQP = \"Sc zAKMRXa r vpnAZtROW ipting wKXBczC Cut ile jmmAZXoGmUSHwv System yG OgnZr Obj wSFqHN ect mtvJpex Ujmzi\".spli" ascii
    $s5  = "var HsK = (\"2.XMLHTTP CRThzBi VCQGr XML ream St mPJUuUJW AD oIyZCcd O bYqx D\").split(\" \");" fullword ascii
    $s6  = "HfIjm.open(laAIQ,pShye,false);" fullword ascii
    $s7  = "if(E>=O.length) {break;}" fullword ascii
    $s8  = "function ceLK(ljECG) {" fullword ascii
    $s9  = "function TFEf(vIKed,gIxuu) {" fullword ascii
    $s10 = "function SrMUfuCsH() {" fullword ascii
    $s11 = "function TArwkWQ(jRvb) {" fullword ascii
    $s12 = "function EmPW(uPAli) {" fullword ascii
    $s13 = "return new ActiveXObject(cpgtsl);" fullword ascii
    $s14 = "return paNND.status;" fullword ascii
    $s15 = "function tIgB(uJuGM) {" fullword ascii
    $s16 = "gyW = E; break; " fullword ascii
    $s17 = "function QRKC(Mrtka) {" fullword ascii
    $s18 = "return DMYBskA(mH,wewES[986-980]+wewES[461-454]+wewES[186-178]);" fullword ascii
    $s19 = "function waDV(AolqI) {" fullword ascii
    $s20 = "if (i >= ljECG.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}