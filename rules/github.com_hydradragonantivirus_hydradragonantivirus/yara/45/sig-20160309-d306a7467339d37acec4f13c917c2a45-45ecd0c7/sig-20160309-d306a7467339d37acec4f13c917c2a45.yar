rule sig_20160309_d306a7467339d37acec4f13c917c2a45 {
  meta:
    description = "datamaliciousorder - file 20160309_d306a7467339d37acec4f13c917c2a45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbce828d4d278150ee6ffe109dd2f466aa21d8bf0142365e28e7186f29d102c8"

  strings:
    $s1  = "var uSp = Fthm(boON + \"B.\" + KSQ[5]+(728898, KSQ[4]));" fullword ascii
    $s2  = "var gF = true  , boON = KSQ[7] + KSQ[9] + KSQ[11];" fullword ascii
    $s3  = "return oqRMaIz[0] + oqRMaIz[2] + oqRMaIz[4] + \".F\" + oqRMaIz[7] + oqRMaIz[9] + oqRMaIz[12] + oqRMaIz[14];" fullword ascii
    $s4  = "var oqRMaIz = \"Sc RDSimHZ r CYrWMbeoD ipting DfZcHID ote ile dgDSkJTwTfNfEa System vP sxMXg Obj qBsyPf ect fJJvEYA\".split(\" " ascii
    $s5  = "var KSQ = (\"2.XMLHTTP PuFJQlr lXGyM XML ream St CvlpXtCz AD BzNkxow O Kyrc D\").split(\" \");" fullword ascii
    $s6  = "VWjwJ.open(dtjCx,IKCVg,false);" fullword ascii
    $s7  = "function LExID(VgasXB) {" fullword ascii
    $s8  = "function EcDWyhcL(LNK) {" fullword ascii
    $s9  = "function yCfEDqZ(NIbs) {" fullword ascii
    $s10 = "function dCyt(VWjwJ,IKCVg,dtjCx) {" fullword ascii
    $s11 = "return LNK.size;" fullword ascii
    $s12 = "return BDxLPvc(JI,WuOZR[883-877]+WuOZR[901-894]+WuOZR[127-119]);" fullword ascii
    $s13 = "function SntM(DTAJx,nRBCH) {" fullword ascii
    $s14 = "function ImnizvIi() {" fullword ascii
    $s15 = "function dGhTGpMhb(AZqKSTROobV) {" fullword ascii
    $s16 = "function cebQ(IWfTs) {" fullword ascii
    $s17 = "if(t>=J.length) {break;}" fullword ascii
    $s18 = "function Qxoy(RGnbV) {" fullword ascii
    $s19 = "function rogMtYfS(JYAmA,iXAaEE) {" fullword ascii
    $s20 = "Ekd = t; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}