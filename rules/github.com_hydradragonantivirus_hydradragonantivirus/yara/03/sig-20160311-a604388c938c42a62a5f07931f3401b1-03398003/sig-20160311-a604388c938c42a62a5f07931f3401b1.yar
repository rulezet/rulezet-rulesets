rule sig_20160311_a604388c938c42a62a5f07931f3401b1 {
  meta:
    description = "datamaliciousorder - file 20160311_a604388c938c42a62a5f07931f3401b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be0427c22bb3165725bb758c3388702c7a36e32966b1088f66b14661a83cdab4"

  strings:
    $s1  = "return FsZMYYl[0] + FsZMYYl[2] + FsZMYYl[4] + \".F\" + FsZMYYl[7] + FsZMYYl[9] + FsZMYYl[12] + FsZMYYl[14];" fullword ascii
    $s2  = "var An = true  , pqev = ttY[7] + ttY[9] + ttY[11];" fullword ascii
    $s3  = "XMTYa.open(JVxuA,bwMkl,false);" fullword ascii
    $s4  = "var ttY = (\"2.XMLHTTP TTQGfLQ XsZan XML ream St OMWETRtK AD EEmHPHJ O FKED D\").split(\" \");" fullword ascii
    $s5  = "var FsZMYYl = \"Sc zZYhUqt r fffQUgoos ipting chFRrGK pSp ile VUStKnWuutRCCB System mE bnImq Obj DmXZBN ect XfwHwkH\".split(\" " ascii
    $s6  = "return fEwtE.status;" fullword ascii
    $s7  = "function MeHDAyWFP(hkTjRPVbrNa) {" fullword ascii
    $s8  = "function PBfmDgMH(FKYuj,IiTvMK) {" fullword ascii
    $s9  = "function AinH(IQXNe,eWaUA) {" fullword ascii
    $s10 = "function EQuj(vIFTN) {" fullword ascii
    $s11 = "function ZhjuQecm() {" fullword ascii
    $s12 = "return NdLm.ExpandEnvironmentStrings(lfVUf);" fullword ascii
    $s13 = "function JqQT(lJfnt) {" fullword ascii
    $s14 = "return SvGX.responseBody;" fullword ascii
    $s15 = "return HZLlkTv" fullword ascii
    $s16 = "if (JdNyH > 126399-954){return true;} else {return false;}" fullword ascii
    $s17 = "function bZli(WTXyL,SktFO) {" fullword ascii
    $s18 = "function MkwP(mUMWm) {" fullword ascii
    $s19 = "function aAzyZGeuF() {" fullword ascii
    $s20 = "function jgWN(uWWQV) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}