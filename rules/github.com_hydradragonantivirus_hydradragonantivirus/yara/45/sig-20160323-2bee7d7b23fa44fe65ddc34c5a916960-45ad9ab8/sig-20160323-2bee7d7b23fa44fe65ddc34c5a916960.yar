rule sig_20160323_2bee7d7b23fa44fe65ddc34c5a916960 {
  meta:
    description = "datamaliciousorder - file 20160323_2bee7d7b23fa44fe65ddc34c5a916960.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96720e2f707d984754cc82c746174a4c7be8afca04a2993d064eae16915f206a"

  strings:
    $s1  = "return WScript.CreateObject(RsAoN);" fullword ascii
    $s2  = "var BZ = true  , SYDX = ZqF[7] + ZqF[9] + ZqF[11];" fullword ascii
    $s3  = "return Wuvzmsy[0] + Wuvzmsy[2] + Wuvzmsy[4] + \".F\" + Wuvzmsy[7] + Wuvzmsy[9] + Wuvzmsy[12] + Wuvzmsy[14];" fullword ascii
    $s4  = "ewxE.open(lyzvD,VdCCO,false);" fullword ascii
    $s5  = "var Wuvzmsy = YzJpN(RgilghLWAP+\" \"+\"System uD oNdNU Obj cCICsL ect iTETdOi GYpiY\", \" \");" fullword ascii
    $s6  = "var ZqF = (\"2.XMLHTTP mcQokNC toJPe XML ream St fvKRwqak AD lCluHir O nQel D\").split(\" \");" fullword ascii
    $s7  = "return MMoQ[bySsUA[0]];" fullword ascii
    $s8  = "function oXShO(KXZjZr) {" fullword ascii
    $s9  = "function YPJxPLVn(Hnw) {" fullword ascii
    $s10 = "return KXZjZr/*ko0x2r5yFMIl0KUNsl6rALY0q*/.position=887-887;" fullword ascii
    $s11 = "function MMvrB(vRtXiA) {" fullword ascii
    $s12 = "return JLnYA;" fullword ascii
    $s13 = "MSR = R; break; " fullword ascii
    $s14 = "if (zoYMc == 1092-892){return true;} else {return false;}" fullword ascii
    $s15 = "function DjDV(spTNs) {" fullword ascii
    $s16 = "function aQdv(YsTwN) {" fullword ascii
    $s17 = "return nLFp.ExpandEnvironmentStrings(sWPiz);" fullword ascii
    $s18 = "if (b >= XPNOk.length) {break;}" fullword ascii
    $s19 = "function UaVMrxFFV(FFTiPEeEYVg) {" fullword ascii
    $s20 = "function wszx(RsAoN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}