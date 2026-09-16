rule sig_20160404_4aec45e67b84940e2d44d8e9862268ca {
  meta:
    description = "datamaliciousorder - file 20160404_4aec45e67b84940e2d44d8e9862268ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3553e5981fec6d2bf6272de9a935bedffb5207bf1e7e3f1b70e2a27783d7d9b"

  strings:
    $s1  = "return vPgrvvm[0] + vPgrvvm[2] + vPgrvvm[4] + \".F\" + vPgrvvm[7] + vPgrvvm[9] + vPgrvvm[12] + vPgrvvm[14];" fullword ascii
    $s2  = "var eQ = true  , afcr = bwt[7] + bwt[9] + bwt[11];" fullword ascii
    $s3  = "VqXR.open(fLOJR,oOpTW,false);" fullword ascii
    $s4  = "var bwt = (\"2.XMLHTTP XOrfjsx ijRLU XML ream St rlfanitI AD Ujfjepo O TYRI D\").split(\" \");" fullword ascii
    $s5  = "var vPgrvvm = jxOQk(uohHJeFrjq+\" \"+\"System Wa UcvJG Obj EMuSza ect mKWPBAi GFqNL\", \" \");" fullword ascii
    $s6  = "return Prm.size;" fullword ascii
    $s7  = "vcn = L; break; " fullword ascii
    $s8  = "function dbznAImo(PnCe) {" fullword ascii
    $s9  = "function hUudyx(hjNqwtj) {" fullword ascii
    $s10 = "function MtlR(xXIyn) {" fullword ascii
    $s11 = "function TGES(xgszm) {" fullword ascii
    $s12 = "function hzysUqERv(CSzmjIyqgWM) {" fullword ascii
    $s13 = "function itTPPmXS(Prm) {" fullword ascii
    $s14 = "if(L>=R.length) {break;}" fullword ascii
    $s15 = "function kWpe(hWGWx) {" fullword ascii
    $s16 = "function zBqwOA(eLZa,LXDjxo) {" fullword ascii
    $s17 = "return qjQYEsw;" fullword ascii
    $s18 = "function sbGqt(GAOZva) {" fullword ascii
    $s19 = "function hYXf(kqnIe) {" fullword ascii
    $s20 = "function AKUpL(ZJuGqr) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}