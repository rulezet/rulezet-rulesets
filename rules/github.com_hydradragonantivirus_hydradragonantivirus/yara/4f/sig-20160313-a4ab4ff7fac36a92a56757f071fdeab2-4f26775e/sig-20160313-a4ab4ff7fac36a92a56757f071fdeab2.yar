rule sig_20160313_a4ab4ff7fac36a92a56757f071fdeab2 {
  meta:
    description = "datamaliciousorder - file 20160313_a4ab4ff7fac36a92a56757f071fdeab2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "204c3e4539254d38e04247829a478c64b76ae0e189e932856fbe27c35a6448eb"

  strings:
    $s1  = "return lHXdCtB[0] + lHXdCtB[2] + lHXdCtB[4] + \".F\" + lHXdCtB[7] + lHXdCtB[9] + lHXdCtB[12] + lHXdCtB[14];" fullword ascii
    $s2  = "var QC = true  , WRTd = ztY[7] + ztY[9] + ztY[11];" fullword ascii
    $s3  = "var lHXdCtB = \"Sc KWUxFQp r IikmWqyub ipting DjoEgZY Ton ile ROXTQVebSSJrQg System mw DjznQ Obj gcScbR ect wjRhnDP\".split(\" " ascii
    $s4  = "uorEH.open(WdpdU,sTHQe,false);" fullword ascii
    $s5  = "var ztY = (\"2.XMLHTTP PbBNyZi OWYEt XML ream St fTwOquXM AD gSeBksw O ZFqu D\").split(\" \");" fullword ascii
    $s6  = "if(X>=Q.length) {break;}" fullword ascii
    $s7  = "function aDexByFo(NPT) {" fullword ascii
    $s8  = "return IrEs.ExpandEnvironmentStrings(ihlNV);" fullword ascii
    $s9  = "return MWNG.responseBody;" fullword ascii
    $s10 = "function xyEJ(JDsJw,dDesY) {" fullword ascii
    $s11 = "jzF = X; break; " fullword ascii
    $s12 = "function ETQchbaf() {" fullword ascii
    $s13 = "function JPDzO(Unxnye) {" fullword ascii
    $s14 = "return ZnpJdOq(xa,hKulF[109-103]+hKulF[701-694]+hKulF[218-210]);" fullword ascii
    $s15 = "return Unxnye.position=660-660;" fullword ascii
    $s16 = "function gsXZ(SyYdz,RchFp) {" fullword ascii
    $s17 = "function skNolxB(MWNG) {" fullword ascii
    $s18 = "function iWVQ(KmTdP) {" fullword ascii
    $s19 = "function dGMN(VsjuL) {" fullword ascii
    $s20 = "function MeGU(loulA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}