rule sig_20160411_a47b4a382809f5bc0e4207733d68bedd {
  meta:
    description = "datamaliciousorder - file 20160411_a47b4a382809f5bc0e4207733d68bedd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bceded4715295ccf77be1c09c8311a69233f8eaef57b26371ecf8f805f0a8eb"

  strings:
    $s1  = "var jX = true  , mVUX = vrV[7] + vrV[9] + vrV[11];" fullword ascii
    $s2  = "return gyFhTqK[0] + gyFhTqK[2] + gyFhTqK[4] + \".F\" + gyFhTqK[7] + gyFhTqK[9] + gyFhTqK[12] + gyFhTqK[14];" fullword ascii
    $s3  = "qQvS.open(enMYR,QOtQy,false);" fullword ascii
    $s4  = "var vrV = (\"2.XMLHTTP YMsORDJ eTRmU XML ream St QQXlEHHU AD sKeGAKZ O bvDl D\").split(\" \");" fullword ascii
    $s5  = "return mdiNZBJ;" fullword ascii
    $s6  = "function VToA(LrxGT) {" fullword ascii
    $s7  = "return \"PHNmeQcYjFBwzx\";" fullword ascii
    $s8  = "function kvXfm(OGfLTv) {" fullword ascii
    $s9  = "function qheX(PSKAy) {" fullword ascii
    $s10 = "function QDEjBo(usOo,evEZtJ) {" fullword ascii
    $s11 = "function JzzK(IOJhK) {" fullword ascii
    $s12 = "if (aTXLH == 799-599){return true;} else {return false;}" fullword ascii
    $s13 = "function yldw(nUNXc,QOtQy,enMYR) {" fullword ascii
    $s14 = "function HFRgJgZ(yifO) {" fullword ascii
    $s15 = "function SVnH(cjnxp,YvbNl) {" fullword ascii
    $s16 = "return HHioL.status;" fullword ascii
    $s17 = "return bAEZumx(ZD,jmlmBn+gdNPU[232-224]);" fullword ascii
    $s18 = "return vLh[KYHg[0]](McreI);" fullword ascii
    $s19 = "return nCyMKyk[0];" fullword ascii
    $s20 = "return kFlXje[rVgv[806-806]]=508-508;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}