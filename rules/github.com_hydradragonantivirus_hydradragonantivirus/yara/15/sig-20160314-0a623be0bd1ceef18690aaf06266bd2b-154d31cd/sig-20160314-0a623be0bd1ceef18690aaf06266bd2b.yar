rule sig_20160314_0a623be0bd1ceef18690aaf06266bd2b {
  meta:
    description = "datamaliciousorder - file 20160314_0a623be0bd1ceef18690aaf06266bd2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e385433aa8fcf1aba53314a0db1f665e0221a9b36231e65724c21198c1632db1"

  strings:
    $s1  = "var Vt = true  , DbHW = kQP[7] + kQP[9] + kQP[11];" fullword ascii
    $s2  = "return doOXbrZ[0] + doOXbrZ[2] + doOXbrZ[4] + \".F\" + doOXbrZ[7] + doOXbrZ[9] + doOXbrZ[12] + doOXbrZ[14];" fullword ascii
    $s3  = "var doOXbrZ = \"Sc mFlGfFJ r llNWCnbPF ipting hrHjjfj jyi ile wZLBbDbdSVVEqc System hy rzHfl Obj zWEEEB ect QCZJmiI RIwUt\".spli" ascii
    $s4  = "var kQP = (\"2.XMLHTTP IutrSVW QHLgr XML ream St VGlwZOks AD UjqmhdX O baMr D\").split(\" \");" fullword ascii
    $s5  = "var doOXbrZ = \"Sc mFlGfFJ r llNWCnbPF ipting hrHjjfj jyi ile wZLBbDbdSVVEqc System hy rzHfl Obj zWEEEB ect QCZJmiI RIwUt\".spli" ascii
    $s6  = "XfZvU.open(vUbic,TbIaX,false);" fullword ascii
    $s7  = "if(p>=b.length) {break;}" fullword ascii
    $s8  = "function ofQDJYBjF() {" fullword ascii
    $s9  = "function CJrK(EFfQT) {" fullword ascii
    $s10 = "function jCgO(XfZvU,TbIaX,vUbic) {" fullword ascii
    $s11 = "function YBWf(dsQIc) {" fullword ascii
    $s12 = "return KEfpcGT(OI,FtmFD[387-381]+FtmFD[978-971]+FtmFD[345-337]);" fullword ascii
    $s13 = "return etOGAc.position=294-294;" fullword ascii
    $s14 = "Zjj = p; break; " fullword ascii
    $s15 = "function KEfpcGT(tIyO,NVonb) {" fullword ascii
    $s16 = "function FjDe(fUOvH,fsUqj) {" fullword ascii
    $s17 = "function FLDF(jPWNy,UiCYa) {" fullword ascii
    $s18 = "return hhfuH.status;" fullword ascii
    $s19 = "function dRwIHyN(KvfG) {" fullword ascii
    $s20 = "return FasTO;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}