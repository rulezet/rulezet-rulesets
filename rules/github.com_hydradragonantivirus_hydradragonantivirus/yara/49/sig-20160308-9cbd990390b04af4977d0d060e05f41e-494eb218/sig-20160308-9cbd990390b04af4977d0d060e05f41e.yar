rule sig_20160308_9cbd990390b04af4977d0d060e05f41e {
  meta:
    description = "datamaliciousorder - file 20160308_9cbd990390b04af4977d0d060e05f41e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07094ce8b37d2f33bb0b2cc1fd5c0930a422ccefd7621f30ad13457b408e709c"

  strings:
    $s1  = "var mX = true  , IRyi = BpT[7] + BpT[9] + BpT[11];" fullword ascii
    $s2  = "return FkhOgoU[0] + FkhOgoU[2] + FkhOgoU[4] + \".F\" + FkhOgoU[7] + FkhOgoU[9] + FkhOgoU[12] + FkhOgoU[14];" fullword ascii
    $s3  = "zVXyQ.open(XJfAb,nFIlM,false);" fullword ascii
    $s4  = "var FkhOgoU = \"Sc OmwYhyC r GCttbGUXH ipting qvhzwCo HWh ile iVpIsCvekWBWoI System pq ZAWHX Obj QiXOXY ect wWimjpD\".split(\" " ascii
    $s5  = "var BpT = (\"2.XMLHTTP nTJIVeE SzDhr XML ream St wZNNJAOt AD JibqabK O mxks D\").split(\" \");" fullword ascii
    $s6  = "function NuTe(zVXyQ,nFIlM,XJfAb) {" fullword ascii
    $s7  = "function qKviGocF() {" fullword ascii
    $s8  = "return YMsYy;" fullword ascii
    $s9  = "function UNdH(npvvK) {" fullword ascii
    $s10 = "return ij.ExpandEnvironmentStrings(UQNGX[6]+UQNGX[7]+UQNGX[8]);" fullword ascii
    $s11 = "return yEPmTjR" fullword ascii
    $s12 = "function fqsTccqLY(XoqLRLCrhQq) {" fullword ascii
    $s13 = "return bMheZ.status;" fullword ascii
    $s14 = "function TqGLcGuLn(EKKCu,tmAOe,whJLT,mjwN) {" fullword ascii
    $s15 = "function yXyGTIsP(hKj) {" fullword ascii
    $s16 = "function vMjQ(VKAYZ) {" fullword ascii
    $s17 = "if (CejQw == 736-536){return true;} else {return false;}" fullword ascii
    $s18 = "function dWZCd(znCvAb) {" fullword ascii
    $s19 = "return ygcU.responseBody;" fullword ascii
    $s20 = "function dXKO(LrGGa) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}