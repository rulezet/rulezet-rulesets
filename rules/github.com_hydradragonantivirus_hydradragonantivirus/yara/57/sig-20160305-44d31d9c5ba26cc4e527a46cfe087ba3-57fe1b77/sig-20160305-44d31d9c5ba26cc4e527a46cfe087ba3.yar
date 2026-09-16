rule sig_20160305_44d31d9c5ba26cc4e527a46cfe087ba3 {
  meta:
    description = "datamaliciousorder - file 20160305_44d31d9c5ba26cc4e527a46cfe087ba3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93aec8a0e196d854d4bf7880a3ca1257614eac21ac1f1d23ab3b1d145a364d7b"

  strings:
    $s1  = "var BrbGY = \"iotZuY cpK pt.Shell vRBsyfr Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var rDe = (SUs + \"TTP\" + \" qbaOyHs oHCTc XML ream St YxZbQqOo AD Aieuqrx OD\").split(\" \");" fullword ascii
    $s3  = "return AXaAOdu[0] + AXaAOdu[2] + AXaAOdu[4] + \".F\" + AXaAOdu[7] + AXaAOdu[9] + AXaAOdu[12] + AXaAOdu[14];" fullword ascii
    $s4  = "var lw = true  , RNBj = rDe[7] + \"\" + rDe[9];" fullword ascii
    $s5  = "var AXaAOdu = \"Sc bEnmQtD r hybOzzBrK ipting XsbhsGW EuC ile kWhuikUBwVtwVS System xv TnPQp Obj vdxPMU ect pSBVHbT\".split(\" " ascii
    $s6  = "pEeNU.open(nofJd,qnHPY,false);" fullword ascii
    $s7  = "function EicK(VrVcl) {" fullword ascii
    $s8  = "function WsvMysK(uiNE) {" fullword ascii
    $s9  = "return HdNgX;" fullword ascii
    $s10 = "function fphP(foDuZ) {" fullword ascii
    $s11 = "function SJMY(VjlsE) {" fullword ascii
    $s12 = "function afkL(FmTRN) {" fullword ascii
    $s13 = "if (VjlsE > 168307-238){return true;} else {return false;}" fullword ascii
    $s14 = "return msDKfQG" fullword ascii
    $s15 = "function hjnRbsqgw(oiNfR,puPMk,kMLWG) {" fullword ascii
    $s16 = "function lqog(pEeNU,qnHPY,nofJd) {" fullword ascii
    $s17 = "function TWus(axDmC,geYbb) {" fullword ascii
    $s18 = "function AIuL(DUOOX) {" fullword ascii
    $s19 = "return new ActiveXObject(dBkJul);" fullword ascii
    $s20 = "BjF = T; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}