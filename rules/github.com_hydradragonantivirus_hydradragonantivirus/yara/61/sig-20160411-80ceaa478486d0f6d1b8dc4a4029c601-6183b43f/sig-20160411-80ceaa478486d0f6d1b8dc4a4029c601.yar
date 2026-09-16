rule sig_20160411_80ceaa478486d0f6d1b8dc4a4029c601 {
  meta:
    description = "datamaliciousorder - file 20160411_80ceaa478486d0f6d1b8dc4a4029c601.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b3eeff037fcf1d6b5f4db0932d1385a3ba26daa1220e5c5b29d67c086c0a991"

  strings:
    $s1  = "return EmdtXuc[0] + EmdtXuc[2] + EmdtXuc[4] + \".F\" + EmdtXuc[7] + EmdtXuc[9] + EmdtXuc[12] + EmdtXuc[14];" fullword ascii
    $s2  = "var EG = true  , zRdY = Sfl[7] + Sfl[9] + Sfl[11];" fullword ascii
    $s3  = "rakM.open(WRTsp,CsVBK,false);" fullword ascii
    $s4  = "if (nOqFQ > 162161-811){return true;} else {return false;}" fullword ascii
    $s5  = "return SpCT[RQnkIPs[0]+RQnkIPs[1]];" fullword ascii
    $s6  = "function mBky(IVHvI) {" fullword ascii
    $s7  = "return UfoPhFJ[0];" fullword ascii
    $s8  = "function vJjcdAvjq(xsMExTqcCVF) {" fullword ascii
    $s9  = "function NSmg(EAkld) {" fullword ascii
    $s10 = "if(d>=X.length) {break;}" fullword ascii
    $s11 = "return xkQob;" fullword ascii
    $s12 = "function LvSKOMHc(PlE) {" fullword ascii
    $s13 = "if (XmRAa == 559-359){return true;} else {return false;}" fullword ascii
    $s14 = "function qBWDF(KpH,qsXdy) {" fullword ascii
    $s15 = "return PlE.size;" fullword ascii
    $s16 = "if (N >= IVHvI.length) {break;}" fullword ascii
    $s17 = "function UqgLS(gnQCIv) {" fullword ascii
    $s18 = "function iQPX(KEUAi,CsVBK,WRTsp) {" fullword ascii
    $s19 = "return KpH[TMvD[0]](qsXdy);" fullword ascii
    $s20 = "function DVoABO(vfhvddo) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}