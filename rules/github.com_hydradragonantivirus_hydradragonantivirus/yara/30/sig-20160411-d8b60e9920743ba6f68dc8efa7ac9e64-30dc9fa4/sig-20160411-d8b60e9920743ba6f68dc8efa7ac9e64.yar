rule sig_20160411_d8b60e9920743ba6f68dc8efa7ac9e64 {
  meta:
    description = "datamaliciousorder - file 20160411_d8b60e9920743ba6f68dc8efa7ac9e64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b4e91946c2a994aed9e7941b4460d5b605bb3f8b334c1857fda80105297f14b"

  strings:
    $s1  = "return xaFcvFr[0] + xaFcvFr[2] + xaFcvFr[4] + \".F\" + xaFcvFr[7] + xaFcvFr[9] + xaFcvFr[12] + xaFcvFr[14];" fullword ascii
    $s2  = "var Uh = true  , QhiK = hRM[7] + hRM[9] + hRM[11];" fullword ascii
    $s3  = "Ouif.open(nqiSA,CLBle,false);" fullword ascii
    $s4  = "var hRM = (\"2.XMLHTTP AbPPSuA RFYrS XML ream St frNGiwrL AD lpgNVFX O CEil D\").split(\" \");" fullword ascii
    $s5  = "return rJvwHM[wNfK[398-398]]=243-243;" fullword ascii
    $s6  = "function obZb(IBlZz) {" fullword ascii
    $s7  = "function lFeAFQ(JQII,XZtClL) {" fullword ascii
    $s8  = "function sRnxVHOQ(Pxn) {" fullword ascii
    $s9  = "function ToGoD(yBdzmW) {" fullword ascii
    $s10 = "function VJVU(DwjBu) {" fullword ascii
    $s11 = "function RppRijA(zBvs,AGCcQ) {" fullword ascii
    $s12 = "return zLjEJ;" fullword ascii
    $s13 = "function RiTS(Ejgqr) {" fullword ascii
    $s14 = "function uqGSi(lDs,dHszI) {" fullword ascii
    $s15 = "if (IBlZz == 442-242){return true;} else {return false;}" fullword ascii
    $s16 = "function KXXsAU(WQTRhAq) {" fullword ascii
    $s17 = "return lWiDYXR[0];" fullword ascii
    $s18 = "function TbuFw(hruPRNQR,PscD) {" fullword ascii
    $s19 = "function jkvQzdojs(UGvfu) {" fullword ascii
    $s20 = "return lDs[PjaJ[0]](dHszI);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}