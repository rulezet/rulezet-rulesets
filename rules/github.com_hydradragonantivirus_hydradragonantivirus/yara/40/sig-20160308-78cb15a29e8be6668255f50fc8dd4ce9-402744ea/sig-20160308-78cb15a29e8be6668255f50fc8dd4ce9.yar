rule sig_20160308_78cb15a29e8be6668255f50fc8dd4ce9 {
  meta:
    description = "datamaliciousorder - file 20160308_78cb15a29e8be6668255f50fc8dd4ce9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "305a61d79d334ec77ddca8467f52a76b0683085edd0e70d9a5a2d5a878525537"

  strings:
    $s1  = "return wsSLdHy[0] + wsSLdHy[2] + wsSLdHy[4] + \".F\" + wsSLdHy[7] + wsSLdHy[9] + wsSLdHy[12] + wsSLdHy[14];" fullword ascii
    $s2  = "var jZ = true  , makf = XXU[7] + XXU[9] + XXU[11];" fullword ascii
    $s3  = "var XXU = (\"2.XMLHTTP ilvzEdJ lneyu XML ream St EPHUuIqi AD cdJvxlL O elVL D\").split(\" \");" fullword ascii
    $s4  = "var wsSLdHy = \"Sc ukUKyOY r NEiRgXUcv ipting RIFSaen TSD ile HDwmaLmKCbbUNd System sq RfmrX Obj GKKZhu ect LGdgRCj\".split(\" " ascii
    $s5  = "VIhPz.open(BqMkF,aAgpV,false);" fullword ascii
    $s6  = "if(T>=S.length) {break;}" fullword ascii
    $s7  = "return GKhBR;" fullword ascii
    $s8  = "function UPAW(dVFlK,BhOJo) {" fullword ascii
    $s9  = "return LiSD.responseBody;" fullword ascii
    $s10 = "function UMYr(ERpZP) {" fullword ascii
    $s11 = "ZNt = T; break; " fullword ascii
    $s12 = "function sjWQ(GLJqt) {" fullword ascii
    $s13 = "function VtwL(DaXUB) {" fullword ascii
    $s14 = "function idDJcxBY() {" fullword ascii
    $s15 = "return txCJKPj" fullword ascii
    $s16 = "return nx.ExpandEnvironmentStrings(oRxcG[6]+oRxcG[7]+oRxcG[8]);" fullword ascii
    $s17 = "function RcjR(vgHJB) {" fullword ascii
    $s18 = "if (r >= sbaLj.length) {break;}" fullword ascii
    $s19 = "function dFtZ(sbaLj) {" fullword ascii
    $s20 = "function sMrEORIPt(KMzDPGJycpH) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}