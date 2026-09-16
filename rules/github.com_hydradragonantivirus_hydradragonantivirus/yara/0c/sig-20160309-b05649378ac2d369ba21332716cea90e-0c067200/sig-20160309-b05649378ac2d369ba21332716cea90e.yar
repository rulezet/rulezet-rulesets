rule sig_20160309_b05649378ac2d369ba21332716cea90e {
  meta:
    description = "datamaliciousorder - file 20160309_b05649378ac2d369ba21332716cea90e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f8f0007f437b4cf355913722568b95112a3786be6d24c0980cb4bb72af94d96"

  strings:
    $s1  = "return niHhznZ[0] + niHhznZ[2] + niHhznZ[4] + \".F\" + niHhznZ[7] + niHhznZ[9] + niHhznZ[12] + niHhznZ[14];" fullword ascii
    $s2  = "var Lg = true  , BOzP = kZz[7] + kZz[9] + kZz[11];" fullword ascii
    $s3  = "var kZz = (\"2.XMLHTTP CKCYBHq AggSW XML ream St ZmQHofQK AD RMCTfXI O RPdr D\").split(\" \");" fullword ascii
    $s4  = "RRcVI.open(fbhZT,gPOZN,false);" fullword ascii
    $s5  = "return oyD.size;" fullword ascii
    $s6  = "function eQfNGLk(lpXV) {" fullword ascii
    $s7  = "function tXokfUb(rhDZ,zOHes) {" fullword ascii
    $s8  = "return tXokfUb(ri,gHxUF[719-713]+gHxUF[808-801]+gHxUF[916-908]);" fullword ascii
    $s9  = "if (Y >= pGqop.length) {break;}" fullword ascii
    $s10 = "return ouOhdkC" fullword ascii
    $s11 = "function EQmKtOdU(kBzEP,GfpKqW) {" fullword ascii
    $s12 = "function AnAB(OEGeJ) {" fullword ascii
    $s13 = "function wToDJwcu() {" fullword ascii
    $s14 = "function vnOl(RRcVI,gPOZN,fbhZT) {" fullword ascii
    $s15 = "return rhDZ.ExpandEnvironmentStrings(zOHes);" fullword ascii
    $s16 = "if (uapVz > 180217-679){return true;} else {return false;}" fullword ascii
    $s17 = "function BTns(perWd,FwrIF) {" fullword ascii
    $s18 = "function eBYxPtEH(oyD) {" fullword ascii
    $s19 = "if(k>=g.length) {break;}" fullword ascii
    $s20 = "function rNNG(PwbfO,Zebel) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}