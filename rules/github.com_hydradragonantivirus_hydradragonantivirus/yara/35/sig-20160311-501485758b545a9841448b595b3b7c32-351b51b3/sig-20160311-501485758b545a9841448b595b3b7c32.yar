rule sig_20160311_501485758b545a9841448b595b3b7c32 {
  meta:
    description = "datamaliciousorder - file 20160311_501485758b545a9841448b595b3b7c32.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb4e37e3f37f00d1c94c5ddecc520c4fa3ca29f47c2e38340650abb3c7d0a7fa"

  strings:
    $s1  = "var Gb = true  , HlVa = WHE[7] + WHE[9] + WHE[11];" fullword ascii
    $s2  = "return pBHDqeF[0] + pBHDqeF[2] + pBHDqeF[4] + \".F\" + pBHDqeF[7] + pBHDqeF[9] + pBHDqeF[12] + pBHDqeF[14];" fullword ascii
    $s3  = "var pBHDqeF = \"Sc RLYQeTk r jPwoBLUJU ipting EVPXNjE RTL ile MgaBTfmcqPqoWm System oT KpQwt Obj DgXPEY ect NEUSdvt\".split(\" " ascii
    $s4  = "zcjIh.open(QYxvd,jptJj,false);" fullword ascii
    $s5  = "var WHE = (\"2.XMLHTTP MDoUJjj XbTQm XML ream St KiiBsEgx AD hcSczfQ O lwWp D\").split(\" \");" fullword ascii
    $s6  = "function wyxBBowC() {" fullword ascii
    $s7  = "ELX = o; break; " fullword ascii
    $s8  = "return mrFB.responseBody;" fullword ascii
    $s9  = "function tdfCg(vejHjS) {" fullword ascii
    $s10 = "if (bvUVa > 137954-553){return true;} else {return false;}" fullword ascii
    $s11 = "return KuWEI.status;" fullword ascii
    $s12 = "function nxSJ(IaBJl) {" fullword ascii
    $s13 = "function srtu(bpaKt) {" fullword ascii
    $s14 = "function UbDBoEVZ(RPx) {" fullword ascii
    $s15 = "function mBaw(KuWEI) {" fullword ascii
    $s16 = "function GKYO(FICbE) {" fullword ascii
    $s17 = "return RsRKcbd(uc,aDbpS[295-289]+aDbpS[236-229]+aDbpS[551-543]);" fullword ascii
    $s18 = "if (C >= XYSPj.length) {break;}" fullword ascii
    $s19 = "return new ActiveXObject(GqgGpq);" fullword ascii
    $s20 = "function rnYX(GqIsX) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}