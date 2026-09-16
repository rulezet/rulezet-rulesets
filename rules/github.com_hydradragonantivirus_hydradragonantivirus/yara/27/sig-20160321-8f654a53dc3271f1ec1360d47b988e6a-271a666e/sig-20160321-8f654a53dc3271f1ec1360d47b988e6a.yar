rule sig_20160321_8f654a53dc3271f1ec1360d47b988e6a {
  meta:
    description = "datamaliciousorder - file 20160321_8f654a53dc3271f1ec1360d47b988e6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fde08dd6db939818e43b1a87cf8a960fc44a7a7c77252d64d6fa04f5a6045f85"

  strings:
    $s1  = "return WScript.CreateObject(GHxjL);" fullword ascii
    $s2  = "var nT = true  , yCnZ = DhZ[7] + DhZ[9] + DhZ[11];" fullword ascii
    $s3  = "return NNpOjFy[0] + NNpOjFy[2] + NNpOjFy[4] + \".F\" + NNpOjFy[7] + NNpOjFy[9] + NNpOjFy[12] + NNpOjFy[14];" fullword ascii
    $s4  = "UEJau.open(reeNv,lkZAD,false);" fullword ascii
    $s5  = "var NNpOjFy = aTHKl(LuPGwmoROL+\" \"+\"System wC faXxJ Obj VNhTLD ect ONichVR BkjXa\", \" \");" fullword ascii
    $s6  = "var DhZ = (\"2.XMLHTTP KUCGqVH FwRDh XML ream St LEmSNGmI AD tCfFVRc O jWHh D\").split(\" \");" fullword ascii
    $s7  = "if(A>=B.length) {break;}" fullword ascii
    $s8  = "var QM = fuCi(Hz).split(\" \");" fullword ascii
    $s9  = "function BmoCtfy(RhXl) {" fullword ascii
    $s10 = "function aTHKl(IOm,tozUX) {" fullword ascii
    $s11 = "function krQH(UEJau,lkZAD,reeNv) {" fullword ascii
    $s12 = "function mTwx(GgTAF,GNSDu) {" fullword ascii
    $s13 = "function fuCi(upDXG) {" fullword ascii
    $s14 = "if (HxKzg > 195347-225){return true;} else {return false;}" fullword ascii
    $s15 = "if (nqVWu == 1164-964){return true;} else {return false;}" fullword ascii
    $s16 = "function OaQpdQXq(LTWU) {" fullword ascii
    $s17 = "return RhXl[kJZucj[0]];" fullword ascii
    $s18 = "return lvosG.status;" fullword ascii
    $s19 = "function Ghif(GHxjL) {" fullword ascii
    $s20 = "if (w >= upDXG.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}