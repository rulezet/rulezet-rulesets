rule sig_20160324_b682234814bf16b146424ecb47ed520f {
  meta:
    description = "datamaliciousorder - file 20160324_b682234814bf16b146424ecb47ed520f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "918154b4a0a67b65ecd34d2d3776df3013b83b55c6ea5b502d7d5a2d9259ba2f"

  strings:
    $s1  = "return WScript.CreateObject(JZWFW);" fullword ascii
    $s2  = "var rz = true  , meNX = vcJ[7] + vcJ[9] + vcJ[11];" fullword ascii
    $s3  = "return Gmgtest[0] + Gmgtest[2] + Gmgtest[4] + \".F\" + Gmgtest[7] + Gmgtest[9] + Gmgtest[12] + Gmgtest[14];" fullword ascii
    $s4  = "RLfT.open(STugF,vcyaY,false);" fullword ascii
    $s5  = "var vcJ = (\"2.XMLHTTP ibmzKGf TPtRN XML ream St ULWAVFsH AD HcggBfp O IzHm D\").split(\" \");" fullword ascii
    $s6  = "var Gmgtest = pGLjP(sHFYkRCgwu+\" \"+\"System jo vtavs Obj bcVSlL ect nMPafFe jBvhE\", \" \");" fullword ascii
    $s7  = "if(q>=C.length) {break;}" fullword ascii
    $s8  = "if (i >= epPIl.length) {break;}" fullword ascii
    $s9  = "return MHXG[FUfvuh[0]];" fullword ascii
    $s10 = "return pij.size;" fullword ascii
    $s11 = "function jxaR(uQjFr) {" fullword ascii
    $s12 = "function PdmGNaeG(pij) {" fullword ascii
    $s13 = "if (aLYkC == 1027-827){return true;} else {return false;}" fullword ascii
    $s14 = "function xfGeSni(MHXG) {" fullword ascii
    $s15 = "function TMbkU(xqltXH) {" fullword ascii
    $s16 = "return hxwhuPb(Hz,xOtqk[252-246]+xOtqk[156-149]+xOtqk[785-777]);" fullword ascii
    $s17 = "function zGyms(feuwgXbV,qcZz) {" fullword ascii
    $s18 = "return PAP.split(uDrkC);" fullword ascii
    $s19 = "Zxr = q; break; " fullword ascii
    $s20 = "var vJXidBP = \"KCglrL*eVA*pt.S\"+\"hell*kkhxVwt*Scri*\";" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}