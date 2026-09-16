rule sig_20160308_c4683bf62d84ae37953e88da18db8db0 {
  meta:
    description = "datamaliciousorder - file 20160308_c4683bf62d84ae37953e88da18db8db0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d2c9d5a0c92b3a9e9e6c59064db1d231e16a38b1d800c31bf3a12d9c8c28357"

  strings:
    $s1  = "return VkjgNQc[0] + VkjgNQc[2] + VkjgNQc[4] + \".F\" + VkjgNQc[7] + VkjgNQc[9] + VkjgNQc[12] + VkjgNQc[14];" fullword ascii
    $s2  = "var DF = true  , fxsN = vsg[7] + vsg[9] + vsg[11];" fullword ascii
    $s3  = "KVIwX.open(ISXfm,CTBgK,false);" fullword ascii
    $s4  = "var vsg = (\"2.XMLHTTP gFmnjOP YZWLh XML ream St mmJUEexm AD xpqVnaE O gSdy D\").split(\" \");" fullword ascii
    $s5  = "var VkjgNQc = \"Sc fIbmOBV r vOZZlkFyC ipting fpafisV KcM ile dLddJcBziuQfyH System Qi iDoIs Obj gMqjtj ect YAqzeMD\".split(\" " ascii
    $s6  = "return UFRbx;" fullword ascii
    $s7  = "return kNiwxWp" fullword ascii
    $s8  = "return jvb.size;" fullword ascii
    $s9  = "function KADt(CiNEX) {" fullword ascii
    $s10 = "if (VlJYY == 739-539){return true;} else {return false;}" fullword ascii
    $s11 = "function OWCK(VsKFT,kghWP) {" fullword ascii
    $s12 = "function HJXD(mYeHe) {" fullword ascii
    $s13 = "if (M >= mChBn.length) {break;}" fullword ascii
    $s14 = "cqa = i; break; " fullword ascii
    $s15 = "function tIBfm(OWFEdq) {" fullword ascii
    $s16 = "if (NoCXt > 197421-702){return true;} else {return false;}" fullword ascii
    $s17 = "function Rrzd(VlJYY) {" fullword ascii
    $s18 = "function rFmh(sFzxM,sESed) {" fullword ascii
    $s19 = "function URYWAsDVS(BVBnoigxgbA) {" fullword ascii
    $s20 = "return CiNEX.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}