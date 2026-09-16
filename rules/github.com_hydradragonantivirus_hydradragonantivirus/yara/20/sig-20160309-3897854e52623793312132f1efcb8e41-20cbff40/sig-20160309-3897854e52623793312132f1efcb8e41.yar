rule sig_20160309_3897854e52623793312132f1efcb8e41 {
  meta:
    description = "datamaliciousorder - file 20160309_3897854e52623793312132f1efcb8e41.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "192a46bb8952ccc1fcbb620ce5adaf77b67f32949cf4989c1bed0a22ec46f96d"

  strings:
    $s1  = "var fo = true  , mThK = Ngr[7] + Ngr[9] + Ngr[11];" fullword ascii
    $s2  = "return vpQyAiW[0] + vpQyAiW[2] + vpQyAiW[4] + \".F\" + vpQyAiW[7] + vpQyAiW[9] + vpQyAiW[12] + vpQyAiW[14];" fullword ascii
    $s3  = "var Ngr = (\"2.XMLHTTP fdrrWeU IaWis XML ream St fFOQbeoH AD grjHvFc O tSth D\").split(\" \");" fullword ascii
    $s4  = "var vpQyAiW = \"Sc SwylkRk r BbvcXTFik ipting DsNPEMB CCk ile bNXPSEQSepFiHL System GZ wuEsJ Obj yBFoWH ect QIRpfhW\".split(\" " ascii
    $s5  = "gTvIi.open(PaAwp,DfuWz,false);" fullword ascii
    $s6  = "function UisOVATKK(NDvjaiaopLK) {" fullword ascii
    $s7  = "return Obj.size;" fullword ascii
    $s8  = "function znwtfREL(Obj) {" fullword ascii
    $s9  = "function wjOf(hHNxc) {" fullword ascii
    $s10 = "function ZSyD(lSzCr,OjImU) {" fullword ascii
    $s11 = "function voOD(oZxZG,EUxTj) {" fullword ascii
    $s12 = "return gtcSbaZ(tl,RbpWX[790-784]+RbpWX[109-102]+RbpWX[448-440]);" fullword ascii
    $s13 = "function vhgQ(gTvIi,DfuWz,PaAwp) {" fullword ascii
    $s14 = "return new ActiveXObject(hABMTE);" fullword ascii
    $s15 = "function TzqwfuWM() {" fullword ascii
    $s16 = "return spKtF;" fullword ascii
    $s17 = "return rHQQYmo" fullword ascii
    $s18 = "function yrSb(CDdlt) {" fullword ascii
    $s19 = "function gtcSbaZ(AOOZ,lUqBK) {" fullword ascii
    $s20 = "function hXvNHvRPz(NeymC,fFnTJ,fKtdh,uQOi) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}