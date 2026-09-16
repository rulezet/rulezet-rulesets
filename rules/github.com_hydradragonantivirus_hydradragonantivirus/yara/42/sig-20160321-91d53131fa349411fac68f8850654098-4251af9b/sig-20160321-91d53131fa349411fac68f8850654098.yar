rule sig_20160321_91d53131fa349411fac68f8850654098 {
  meta:
    description = "datamaliciousorder - file 20160321_91d53131fa349411fac68f8850654098.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c473fb09705ad4fffd78f24543b1e8382726d490e7a35749da444cabff128e7"

  strings:
    $s1  = "return WScript.CreateObject(vGCLV);" fullword ascii
    $s2  = "function lzlF(LcduA,DLlrv) {" fullword ascii
    $s3  = "return BpqBFwV[0] + BpqBFwV[2] + BpqBFwV[4] + \".F\" + BpqBFwV[7] + BpqBFwV[9] + BpqBFwV[12] + BpqBFwV[14];" fullword ascii
    $s4  = "var Zp = true  , xiJc = zpv[7] + zpv[9] + zpv[11];" fullword ascii
    $s5  = "FKcZq.open(dhKSZ,mXVHJ,false);" fullword ascii
    $s6  = "var BpqBFwV = iFXNv(BjqiRRovYW+\" \"+\"System fn MdwPl Obj mxidHv ect LcDgJtP JTCZZ\", \" \");" fullword ascii
    $s7  = "var zpv = (\"2.XMLHTTP tqMxVpq TLfdP XML ream St JDAVpJjv AD mDBqQBd O kAXy D\").split(\" \");" fullword ascii
    $s8  = "function rDOU(CqlfE) {" fullword ascii
    $s9  = "function PPRj(MDqbp) {" fullword ascii
    $s10 = "return ATG.size;" fullword ascii
    $s11 = "return EkO.split(RuOFC);" fullword ascii
    $s12 = "if (J >= tYoyF.length) {break;}" fullword ascii
    $s13 = "function ViRu(gebjc) {" fullword ascii
    $s14 = "if(m>=w.length) {break;}" fullword ascii
    $s15 = "function zarg(FKcZq,mXVHJ,dhKSZ) {" fullword ascii
    $s16 = "return fkHZWG.position=542-542;" fullword ascii
    $s17 = "function mRqV(SQQfk) {" fullword ascii
    $s18 = "function NhnRt(fkHZWG) {" fullword ascii
    $s19 = "return CqlfE.status;" fullword ascii
    $s20 = "return qTMn.ExpandEnvironmentStrings(FKMTN);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}