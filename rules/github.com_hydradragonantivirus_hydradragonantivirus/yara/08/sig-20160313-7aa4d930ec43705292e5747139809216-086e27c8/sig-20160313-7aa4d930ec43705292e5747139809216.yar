rule sig_20160313_7aa4d930ec43705292e5747139809216 {
  meta:
    description = "datamaliciousorder - file 20160313_7aa4d930ec43705292e5747139809216.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c68cd71ab5218df02a574f5123549fb5927ce9d66b3b37090be6b5c84542ea4"

  strings:
    $s1  = "return gCTkwfq[0] + gCTkwfq[2] + gCTkwfq[4] + \".F\" + gCTkwfq[7] + gCTkwfq[9] + gCTkwfq[12] + gCTkwfq[14];" fullword ascii
    $s2  = "var Bd = true  , arNR = Xdm[7] + Xdm[9] + Xdm[11];" fullword ascii
    $s3  = "var RDT = (\"ht\" + \" jPUHpwL tp nsCYL QVRSClCl :// HBFdBvf .e afoaM x XlckCk e G JfkIWVR E WWnwBtPW T\").split(\" \");" fullword ascii
    $s4  = "var gCTkwfq = \"Sc adEMaGf r CLLFuSNwb ipting IqBmjvc qPN ile smVrVXndOeVljw System Ko zZEJB Obj spAoCn ect nXbwXGS\".split(\" " ascii
    $s5  = "UVOZQ.open(lBWLW,wlFXa,false);" fullword ascii
    $s6  = "var Xdm = (\"2.XMLHTTP vgllWwu uwFvY XML ream St chJzuPCN AD byfBYJu O ixHh D\").split(\" \");" fullword ascii
    $s7  = "function TGvj(SrVkK) {" fullword ascii
    $s8  = "return iCjVA;" fullword ascii
    $s9  = "function YnkBYlSX(NuP) {" fullword ascii
    $s10 = "function nLyM(XZwPM) {" fullword ascii
    $s11 = "function abLr(sgAuD) {" fullword ascii
    $s12 = "if (JFyyC == 1192-992){return true;} else {return false;}" fullword ascii
    $s13 = "if (sgAuD > 189962-860){return true;} else {return false;}" fullword ascii
    $s14 = "return oYaS.responseBody;" fullword ascii
    $s15 = "if(c>=F.length) {break;}" fullword ascii
    $s16 = "return mVkGqM.position=110-110;" fullword ascii
    $s17 = "function JgfXjSbJH(wsmvvCYYvuv) {" fullword ascii
    $s18 = "function EzVL(qqcRH) {" fullword ascii
    $s19 = "function pEjL(HrVBo) {" fullword ascii
    $s20 = "function Culx(UVOZQ,wlFXa,lBWLW) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}