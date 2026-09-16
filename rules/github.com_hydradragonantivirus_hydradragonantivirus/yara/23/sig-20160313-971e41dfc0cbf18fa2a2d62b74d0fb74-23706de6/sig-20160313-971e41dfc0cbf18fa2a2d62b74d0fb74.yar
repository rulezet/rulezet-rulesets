rule sig_20160313_971e41dfc0cbf18fa2a2d62b74d0fb74 {
  meta:
    description = "datamaliciousorder - file 20160313_971e41dfc0cbf18fa2a2d62b74d0fb74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f77c3244f95b4e1d87d22dbd0215d52024860061132e8532e8feb434528a7450"

  strings:
    $s1  = "var rq = true  , bDSg = Bdd[7] + Bdd[9] + Bdd[11];" fullword ascii
    $s2  = "return rlMOWuQ[0] + rlMOWuQ[2] + rlMOWuQ[4] + \".F\" + rlMOWuQ[7] + rlMOWuQ[9] + rlMOWuQ[12] + rlMOWuQ[14];" fullword ascii
    $s3  = "var Bdd = (\"2.XMLHTTP RFisgEd TLRzg XML ream St uGxYpOan AD lkmfIKn O HReP D\").split(\" \");" fullword ascii
    $s4  = "var rlMOWuQ = \"Sc nEaYJue r UugwGoyCJ ipting JqoqPXV DYV ile olVUIYrDTscOpX System be YPDRX Obj fWZCbE ect KVxJeOE\".split(\" " ascii
    $s5  = "baovV.open(xYXVg,PkDma,false);" fullword ascii
    $s6  = "return VxFsB;" fullword ascii
    $s7  = "return kyCcExZ" fullword ascii
    $s8  = "function NycQ(mwkmt) {" fullword ascii
    $s9  = "return DjVtyB.position=714-714;" fullword ascii
    $s10 = "return new ActiveXObject(dGGrkH);" fullword ascii
    $s11 = "function lczDtoylt(XchIsNJtgyM) {" fullword ascii
    $s12 = "return ILBG.responseBody;" fullword ascii
    $s13 = "function YnhHS(dGGrkH) {" fullword ascii
    $s14 = "function dhlR(vVSNq,iEzrq) {" fullword ascii
    $s15 = "function mTte(lDxew) {" fullword ascii
    $s16 = "return bfT.size;" fullword ascii
    $s17 = "if (NvAbY == 636-436){return true;} else {return false;}" fullword ascii
    $s18 = "function GyQw(EKeEf) {" fullword ascii
    $s19 = "function uHin(pYAVp,QpRsS) {" fullword ascii
    $s20 = "function pJfy(NvAbY) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}