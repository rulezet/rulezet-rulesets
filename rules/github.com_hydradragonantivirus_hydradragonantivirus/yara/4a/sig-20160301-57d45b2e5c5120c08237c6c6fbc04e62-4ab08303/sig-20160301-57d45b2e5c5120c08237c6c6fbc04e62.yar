rule sig_20160301_57d45b2e5c5120c08237c6c6fbc04e62 {
  meta:
    description = "datamaliciousorder - file 20160301_57d45b2e5c5120c08237c6c6fbc04e62.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2300b6b4eabc4880329d2cd7fcd287504302f397fe50086308e18e0d8d66c851"

  strings:
    $s1  = "var FY = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(NGaJo);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + MModnvN + \".F\" + IFhSYQmPYo + ghpaG + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var qMF = (rJO + \"TTP\" + \" spWnyxH cwpMH XML ream St vGrcbeAj AD zMDrLVW OD\").split(\" \");" fullword ascii
    $s5  = "var yo = true  , YvMD = qMF[7] + \"\" + qMF[9];" fullword ascii
    $s6  = "NmpsP.open(vMZDE,kjYlN,false);" fullword ascii
    $s7  = "ogs.CreateFolder(Whop);" fullword ascii
    $s8  = "function NQZz(kxguP) {" fullword ascii
    $s9  = "function mdzv(NaeRI) {" fullword ascii
    $s10 = "return new ActiveXObject(nTDqES);" fullword ascii
    $s11 = "return aYPmM.status;" fullword ascii
    $s12 = "function wQDS(pBhjN,unbmV) {" fullword ascii
    $s13 = "function zUCs(bqgcD) {" fullword ascii
    $s14 = "function CgvP(NGaJo) {" fullword ascii
    $s15 = "function ZIPaURtMY(XDBoF,UDACk,xeumy) {" fullword ascii
    $s16 = "fJc = u; break; " fullword ascii
    $s17 = "if (CLUOT == 850-650){return true;} else {return false;}" fullword ascii
    $s18 = "function RhFJ(NmpsP,kjYlN,vMZDE) {" fullword ascii
    $s19 = "function BctafIvM() {" fullword ascii
    $s20 = "if (kavMt > 191053-342){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}