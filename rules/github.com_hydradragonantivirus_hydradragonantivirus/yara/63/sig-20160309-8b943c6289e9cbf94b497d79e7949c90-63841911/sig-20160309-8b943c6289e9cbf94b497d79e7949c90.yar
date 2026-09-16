rule sig_20160309_8b943c6289e9cbf94b497d79e7949c90 {
  meta:
    description = "datamaliciousorder - file 20160309_8b943c6289e9cbf94b497d79e7949c90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5309541a4afa7b286e57e6e35dc5014ed43f063871a3f61865fe6f6ba6d4d338"

  strings:
    $s1  = "return CRDASps[0] + CRDASps[2] + CRDASps[4] + \".F\" + CRDASps[7] + CRDASps[9] + CRDASps[12] + CRDASps[14];" fullword ascii
    $s2  = "var pV = true  , hthn = ygy[7] + ygy[9] + ygy[11];" fullword ascii
    $s3  = "kPAgu.open(YbdUk,txJFs,false);" fullword ascii
    $s4  = "var CRDASps = \"Sc DrQwpzp r cbGNxfCLf ipting PSFiKmu vQa ile NvtdAGKmHecYxM System RD OZpQA Obj nFjRyP ect ABgKpYH\".split(\" " ascii
    $s5  = "var ygy = (\"2.XMLHTTP yRFACuI MBEhX XML ream St vbFPLhLN AD aLQgUXa O wWhT D\").split(\" \");" fullword ascii
    $s6  = "if(W>=q.length) {break;}" fullword ascii
    $s7  = "function MUrdCNM(MfSI) {" fullword ascii
    $s8  = "function fmqikCoA() {" fullword ascii
    $s9  = "return xeokcVL" fullword ascii
    $s10 = "function KrYzg(zSueGc) {" fullword ascii
    $s11 = "function hnSG(SsuFE) {" fullword ascii
    $s12 = "function XamQ(nWaaw,aJMXR) {" fullword ascii
    $s13 = "function kGqP(Sqlsu) {" fullword ascii
    $s14 = "function uvClqZTFr(yrUwF,gzSxj,cNHHi,MUsi) {" fullword ascii
    $s15 = "function BPpdSWZTC(DhENmHKhwHx) {" fullword ascii
    $s16 = "function hktcmlxe(bIK) {" fullword ascii
    $s17 = "if (WFPdI == 843-643){return true;} else {return false;}" fullword ascii
    $s18 = "return IBdXCXX(AS,nJZHn[563-557]+nJZHn[243-236]+nJZHn[266-258]);" fullword ascii
    $s19 = "DWW = W; break; " fullword ascii
    $s20 = "function UgALTJYZ(cvsXG,YvtVKB) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}