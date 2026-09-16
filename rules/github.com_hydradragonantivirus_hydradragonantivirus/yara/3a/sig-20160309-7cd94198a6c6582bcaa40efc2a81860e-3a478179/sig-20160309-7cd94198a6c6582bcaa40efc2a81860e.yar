rule sig_20160309_7cd94198a6c6582bcaa40efc2a81860e {
  meta:
    description = "datamaliciousorder - file 20160309_7cd94198a6c6582bcaa40efc2a81860e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e8cfc08ef0ba84801fff5940b52e755273e2d84c1c96c9177cf8fa16bd7a336"

  strings:
    $s1  = "var wH = true  , EGzX = pmv[7] + pmv[9] + pmv[11];" fullword ascii
    $s2  = "return lVGAQAT[0] + lVGAQAT[2] + lVGAQAT[4] + \".F\" + lVGAQAT[7] + lVGAQAT[9] + lVGAQAT[12] + lVGAQAT[14];" fullword ascii
    $s3  = "var pmv = (\"2.XMLHTTP hBXjPjm ixaMU XML ream St ZvqbExSi AD Ptmnxir O PCpv D\").split(\" \");" fullword ascii
    $s4  = "var lVGAQAT = \"Sc fpFAxCg r rMybgPpyX ipting lxznthO Nsc ile fleQygqzErXxHV System kc WyrJo Obj VgsYQa ect CZMejsC\".split(\" " ascii
    $s5  = "mdoSA.open(fIEJJ,aBRVJ,false);" fullword ascii
    $s6  = "return new ActiveXObject(jrhjmx);" fullword ascii
    $s7  = "function AfdE(omDJt) {" fullword ascii
    $s8  = "return tmNs.ExpandEnvironmentStrings(WqYDE);" fullword ascii
    $s9  = "function wmir(IJAoi) {" fullword ascii
    $s10 = "kp = 1;gNA.position=(823-823);AsOK(gNA,/*yJet23pLR0*/fGrg/*3uxw74HZfZ*/+ndoszbW+Yil[7]+Yil[9]+Yil[11]); try  {" fullword ascii
    $s11 = "function kxpuqdlt(lJW) {" fullword ascii
    $s12 = "function RJKE(TxTdV) {" fullword ascii
    $s13 = "return dBoFH.status;" fullword ascii
    $s14 = "function PYbV(mdoSA,aBRVJ,fIEJJ) {" fullword ascii
    $s15 = "function wHRbzeTTL(nvAsoSzHiBK) {" fullword ascii
    $s16 = "function Hsryl(jrhjmx) {" fullword ascii
    $s17 = "function dyEtOfz(QpzD) {" fullword ascii
    $s18 = "function nQmb(dBoFH) {" fullword ascii
    $s19 = "function SWElkVvH() {" fullword ascii
    $s20 = "function ywTO(xwwrt) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}