rule sig_20160303_c300f8f08dea16d4af6788f4391c3daf {
  meta:
    description = "datamaliciousorder - file 20160303_c300f8f08dea16d4af6788f4391c3daf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58b67d6c55286f9bf1f71a9bc27e28b2053cd0a732c9f106a05f25f7ee1ff46a"

  strings:
    $s1  = "var BYhEx = \"Eyeyoh CAe pt.Shell uECjIGq Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var jZ = true  , wVdW = hsw[7] + \"\" + hsw[9];" fullword ascii
    $s3  = "return KERusyU[0] + KERusyU[2] + KERusyU[4] + \".F\" + KERusyU[7] + KERusyU[9] + KERusyU[12] + KERusyU[14];" fullword ascii
    $s4  = "var hsw = (URL + \"TTP\" + \" jUUrLcw mYLiz XML ream St HrZNdgKa AD BBfJhoJ OD\").split(\" \");" fullword ascii
    $s5  = "AJWrS.open(DZrwe,kmMKq,false);" fullword ascii
    $s6  = "return vcomKMl" fullword ascii
    $s7  = "var KERusyU = \"Sc fHCMxIT r RtnjOlSzu ipting swOnlPh gMd ile MxkyiqHodAzQaw System ay UKbzm Obj wwJLVg ect JWjMWji\".split(\" " ascii
    $s8  = "return ti.ExpandEnvironmentStrings(BYhEx[6]);" fullword ascii
    $s9  = "function WugJg(apvggq) {" fullword ascii
    $s10 = "return etQeB;" fullword ascii
    $s11 = "function HJhb(hvkbH) {" fullword ascii
    $s12 = "if (((new Date())>0,7598243888)) {" fullword ascii
    $s13 = "function zbxu(AeLNy) {" fullword ascii
    $s14 = "function UxRC(USwFX,XmRfd) {" fullword ascii
    $s15 = "function iXdo(OltJi) {" fullword ascii
    $s16 = "function oWpl(sbGHL) {" fullword ascii
    $s17 = "function wIzZ(AJWrS,kmMKq,DZrwe) {" fullword ascii
    $s18 = "return jzjt.responseBody;" fullword ascii
    $s19 = "function MUVBIELx() {" fullword ascii
    $s20 = "ABI = Z; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}