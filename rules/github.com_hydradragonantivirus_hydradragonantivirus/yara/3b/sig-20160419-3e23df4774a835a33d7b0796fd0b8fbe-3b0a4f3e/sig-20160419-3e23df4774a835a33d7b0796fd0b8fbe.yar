rule sig_20160419_3e23df4774a835a33d7b0796fd0b8fbe {
  meta:
    description = "datamaliciousorder - file 20160419_3e23df4774a835a33d7b0796fd0b8fbe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb68957639d390facbadf1b6b86b73f86da11ef38c65f3649b3b73fe5b2775a2"

  strings:
    $s1  = "var Sf = true  , AqhL = TzA[7] + TzA[9] + TzA[11];" fullword ascii
    $s2  = "return apoTLRa[0] + apoTLRa[2] + apoTLRa[4] + \".F\" + apoTLRa[7] + apoTLRa[9] + apoTLRa[12] + apoTLRa[14];" fullword ascii
    $s3  = "uWQx.open(rEAXy,JTrVp,false);" fullword ascii
    $s4  = "function nqAYNyC(VKqp) {" fullword ascii
    $s5  = "return hZkZVkW[0];" fullword ascii
    $s6  = "function lDpL(uHyLA) {" fullword ascii
    $s7  = "function oIidF(pDuyyW) {" fullword ascii
    $s8  = "return ETZ[bOrK[0]](nppPy);" fullword ascii
    $s9  = "function bTTGMP(xBRF,bPcVSP) {" fullword ascii
    $s10 = "function YTTSRT(aIMupjv) {" fullword ascii
    $s11 = "if (xZWaE > 186372-360){return true;} else {return false;}" fullword ascii
    $s12 = "return jpN.size;" fullword ascii
    $s13 = "function Oikb(xZWaE) {" fullword ascii
    $s14 = "function exnJzDfMY(FSbpRtkdeOV) {" fullword ascii
    $s15 = "function LfGn(ADRFz,mfCuf) {" fullword ascii
    $s16 = "function hDxt(hqNtp) {" fullword ascii
    $s17 = "return hqNtp.status;" fullword ascii
    $s18 = "return VKqp[hOyGagX[0]+hOyGagX[1]];" fullword ascii
    $s19 = "if (NuVvn != 438-238){return false;} else {return true;}" fullword ascii
    $s20 = "function KKyVU(bOFGthSa,jSCK) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}