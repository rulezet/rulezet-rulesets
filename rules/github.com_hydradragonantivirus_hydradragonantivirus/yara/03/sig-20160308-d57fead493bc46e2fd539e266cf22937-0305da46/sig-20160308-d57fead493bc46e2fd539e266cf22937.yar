rule sig_20160308_d57fead493bc46e2fd539e266cf22937 {
  meta:
    description = "datamaliciousorder - file 20160308_d57fead493bc46e2fd539e266cf22937.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "316b66067461e284f147287cd2869d4492e3b248ca09b8bfa3b805dfdbed2a46"

  strings:
    $s1  = "var CQ = true  , rpCS = lGM[7] + lGM[9] + lGM[11];" fullword ascii
    $s2  = "return odFFeBk[0] + odFFeBk[2] + odFFeBk[4] + \".F\" + odFFeBk[7] + odFFeBk[9] + odFFeBk[12] + odFFeBk[14];" fullword ascii
    $s3  = "var odFFeBk = \"Sc IMEweYh r wYiwNagOM ipting RQgxfKt eXc ile lqKpALPdjARAri System Bh ZFLur Obj mdpZzA ect zdFtMFJ\".split(\" " ascii
    $s4  = "Qpici.open(RkkHa,dkfrH,false);" fullword ascii
    $s5  = "function GTBj(Psqib) {" fullword ascii
    $s6  = "return ir.ExpandEnvironmentStrings(XPMck[6]+XPMck[7]+XPMck[8]);" fullword ascii
    $s7  = "return jAhjp.status;" fullword ascii
    $s8  = "function mPElXAObq(xXBYa,uMVTD,qFPqW,AfXA) {" fullword ascii
    $s9  = "function ZiZI(jAhjp) {" fullword ascii
    $s10 = "function UcNejrW(ygiZ) {" fullword ascii
    $s11 = "function EKyOYGJF(BXL) {" fullword ascii
    $s12 = "return BXL.size;" fullword ascii
    $s13 = "function fPibC(sXnolo) {" fullword ascii
    $s14 = "function vRyl(CDXBh) {" fullword ascii
    $s15 = "function mVCW(suUvq) {" fullword ascii
    $s16 = "function WoAS(Qpici,dkfrH,RkkHa) {" fullword ascii
    $s17 = "return ygiZ.responseBody;" fullword ascii
    $s18 = "function rtvNUZV(YqdR) {" fullword ascii
    $s19 = "if (CDXBh > 188719-531){return true;} else {return false;}" fullword ascii
    $s20 = "function gSvX(PbbsA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}