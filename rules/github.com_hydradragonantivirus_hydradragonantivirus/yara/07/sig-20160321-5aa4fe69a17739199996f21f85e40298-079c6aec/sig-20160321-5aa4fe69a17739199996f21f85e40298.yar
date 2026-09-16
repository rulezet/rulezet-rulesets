rule sig_20160321_5aa4fe69a17739199996f21f85e40298 {
  meta:
    description = "datamaliciousorder - file 20160321_5aa4fe69a17739199996f21f85e40298.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "769da43259c01518a9915f825e82f30ee276e1b582de2108d98fd45f7e54baf9"

  strings:
    $s1  = "return WScript.CreateObject(YzILR);" fullword ascii
    $s2  = "return MzynUln[0] + MzynUln[2] + MzynUln[4] + \".F\" + MzynUln[7] + MzynUln[9] + MzynUln[12] + MzynUln[14];" fullword ascii
    $s3  = "var WJ = true  , sDQl = FAq[7] + FAq[9] + FAq[11];" fullword ascii
    $s4  = "var FAq = (\"2.XMLHTTP dgeHTnW IgzIp XML ream St yHNNLvEc AD ZKZwMPy O TeJS D\").split(\" \");" fullword ascii
    $s5  = "YJKaF.open(Mhjxj,TUefr,false);" fullword ascii
    $s6  = "var MzynUln = LwitU(hJqVNDPAGH+\" \"+\"System KE UTBps Obj gMqaeB ect DZwnTtF fsPnQ\", \" \");" fullword ascii
    $s7  = "function QAOY(NFWaK) {" fullword ascii
    $s8  = "function kWsNtFwRq(xLcGQ) {" fullword ascii
    $s9  = "return LdcKxVm(IJ,IPJIi[490-484]+IPJIi[216-209]+IPJIi[478-470]);" fullword ascii
    $s10 = "return new ActiveXObject(FsfIGh);" fullword ascii
    $s11 = "function dFOD(YJKaF,TUefr,Mhjxj) {" fullword ascii
    $s12 = "return NFWaK.status;" fullword ascii
    $s13 = "tZP = f; break; " fullword ascii
    $s14 = "function wzbLPJS(aDeI) {" fullword ascii
    $s15 = "function fnvw(Bpxlm,Yxbmj) {" fullword ascii
    $s16 = "return ZLJn.ExpandEnvironmentStrings(axxJZ);" fullword ascii
    $s17 = "function rxYB(OIzfL,yqLrp) {" fullword ascii
    $s18 = "function IOZo(odFcz) {" fullword ascii
    $s19 = "function kNtMg(FsfIGh) {" fullword ascii
    $s20 = "function dptny(Qqvsvl) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}