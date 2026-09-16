rule sig_20160314_800f592a4977967680107e2baf32d9e5 {
  meta:
    description = "datamaliciousorder - file 20160314_800f592a4977967680107e2baf32d9e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad94b114c8cee49c51006fd106183caad5be8df355bf6ba9b47edb6d213c9798"

  strings:
    $s1  = "var BHOSGkT = wKAIs(\"Sc hpXCMdB r UStuFEaHQ ipting SOlRYTt sZP ile CtqIVoBpjiuBIY System NB FuOpE Obj itsTIw ect FOxosKM BNcoq" ascii
    $s2  = "var BHOSGkT = wKAIs(\"Sc hpXCMdB r UStuFEaHQ ipting SOlRYTt sZP ile CtqIVoBpjiuBIY System NB FuOpE Obj itsTIw ect FOxosKM BNcoq" ascii
    $s3  = "var jD = true  , Nhyv = rbO[7] + rbO[9] + rbO[11];" fullword ascii
    $s4  = "return BHOSGkT[0] + BHOSGkT[2] + BHOSGkT[4] + \".F\" + BHOSGkT[7] + BHOSGkT[9] + BHOSGkT[12] + BHOSGkT[14];" fullword ascii
    $s5  = "var rbO = (\"2.XMLHTTP jzepKTe KsfNt XML ream St vpgfpwfx AD eyUYgZt O LtUY D\").split(\" \");" fullword ascii
    $s6  = "SrPLr.open(QqiXO,SeVOT,false);" fullword ascii
    $s7  = "function OwzR(SrPLr,SeVOT,QqiXO) {" fullword ascii
    $s8  = "if (mZgTc == 1057-857){return true;} else {return false;}" fullword ascii
    $s9  = "return SLCo.responseBody;" fullword ascii
    $s10 = "function JApvayME(EJi) {" fullword ascii
    $s11 = "function KGgn(TEITh) {" fullword ascii
    $s12 = "return HOD.split(PJISd);" fullword ascii
    $s13 = "WjC = k; break; " fullword ascii
    $s14 = "function nIus(DrExy,ASzYU) {" fullword ascii
    $s15 = "function qwta(mZgTc) {" fullword ascii
    $s16 = "return Gpkphgt" fullword ascii
    $s17 = "function OUkj(IZjad) {" fullword ascii
    $s18 = "function OpFOp(fbvCrG) {" fullword ascii
    $s19 = "return nmmFg.status;" fullword ascii
    $s20 = "function hnbQ(oFxjq) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}