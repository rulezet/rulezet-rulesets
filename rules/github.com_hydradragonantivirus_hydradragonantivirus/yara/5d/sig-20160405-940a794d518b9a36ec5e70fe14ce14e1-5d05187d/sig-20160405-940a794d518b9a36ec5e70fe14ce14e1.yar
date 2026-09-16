rule sig_20160405_940a794d518b9a36ec5e70fe14ce14e1 {
  meta:
    description = "datamaliciousorder - file 20160405_940a794d518b9a36ec5e70fe14ce14e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ac43d235da0f048740fcf0ef23aa593379ca751f2dc476d1f40dc8c1d076b0d"

  strings:
    $s1  = "return mtjmvPJ[0] + mtjmvPJ[2] + mtjmvPJ[4] + \".F\" + mtjmvPJ[7] + mtjmvPJ[9] + mtjmvPJ[12] + mtjmvPJ[14];" fullword ascii
    $s2  = "var Cz = true  , AUOj = dHj[7] + dHj[9] + dHj[11];" fullword ascii
    $s3  = "var dHj = (\"2.XMLHTTP JmWfqMg bsVnO XML ream St jYrfreQk AD AntFIho O VeeO D\").split(\" \");" fullword ascii
    $s4  = "kckO.open(TVhME,YOZJn,false);" fullword ascii
    $s5  = "function UwpM(kcNDC) {" fullword ascii
    $s6  = "var BRsyHBp = \"CgHixG*OtT*pt.S\"+\"hell*qbTPLbQ*Scri*\";" fullword ascii
    $s7  = "function Bekzds(exnjRHu) {" fullword ascii
    $s8  = "if (kcNDC > 184592-921){return true;} else {return false;}" fullword ascii
    $s9  = "return GpT.split(KUGdR);" fullword ascii
    $s10 = "return GYQ.size;" fullword ascii
    $s11 = "function VZyM(IGeBX,vdEwK) {" fullword ascii
    $s12 = "Bnb = a; break; " fullword ascii
    $s13 = "function UrQe(sptvo) {" fullword ascii
    $s14 = "function AMsR(awIkW) {" fullword ascii
    $s15 = "return ObwB[qnsppP[0]];" fullword ascii
    $s16 = "function prbDs(CxHFIDNI,eWpD) {" fullword ascii
    $s17 = "if (awIkW == 1134-934){return true;} else {return false;}" fullword ascii
    $s18 = "function YaXkhQcit(JzAzZ) {" fullword ascii
    $s19 = "if (T >= Dfcnb.length) {break;}" fullword ascii
    $s20 = "function thgW(Dfcnb) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}