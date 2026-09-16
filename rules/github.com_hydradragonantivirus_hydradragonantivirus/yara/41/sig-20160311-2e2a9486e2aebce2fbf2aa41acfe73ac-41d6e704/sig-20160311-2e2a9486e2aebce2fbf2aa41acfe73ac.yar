rule sig_20160311_2e2a9486e2aebce2fbf2aa41acfe73ac {
  meta:
    description = "datamaliciousorder - file 20160311_2e2a9486e2aebce2fbf2aa41acfe73ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5795fe2b7721cfcbb066cde5cd202c6f8160833731d8f9e76d373b275797b89d"

  strings:
    $s1  = "var lb = true  , fIvZ = tJb[7] + tJb[9] + tJb[11];" fullword ascii
    $s2  = "return wOheXfk[0] + wOheXfk[2] + wOheXfk[4] + \".F\" + wOheXfk[7] + wOheXfk[9] + wOheXfk[12] + wOheXfk[14];" fullword ascii
    $s3  = "jRajU.open(VDetw,SEloK,false);" fullword ascii
    $s4  = "var tJb = (\"2.XMLHTTP MEzMDfH OqWOu XML ream St HsrTIODE AD ydhtyBI O cHDD D\").split(\" \");" fullword ascii
    $s5  = "var wOheXfk = \"Sc OuvxzfS r atPjblQZM ipting QEVHOsw wvN ile xcbXSERZOmZYTM System JO FHTZt Obj eOFLez ect kIhYsTj\".split(\" " ascii
    $s6  = "return hGrLjJT(kx,Ggzlu[753-747]+Ggzlu[552-545]+Ggzlu[275-267]);" fullword ascii
    $s7  = "function IuEB(OfAPO) {" fullword ascii
    $s8  = "function VCXWwKKD(kNE) {" fullword ascii
    $s9  = "if(b>=K.length) {break;}" fullword ascii
    $s10 = "function vhfSPRkLB(UBQHJJwnkGQ) {" fullword ascii
    $s11 = "function VUyzc(wMXWNx) {" fullword ascii
    $s12 = "function mLyE(GiBlj,qJGrd) {" fullword ascii
    $s13 = "function hVWH(IgrHv) {" fullword ascii
    $s14 = "return OfAPO.status;" fullword ascii
    $s15 = "function azcU(WUTHP) {" fullword ascii
    $s16 = "return new ActiveXObject(wMXWNx);" fullword ascii
    $s17 = "if (B >= iogde.length) {break;}" fullword ascii
    $s18 = "function KqPI(VWqcG) {" fullword ascii
    $s19 = "function hGrLjJT(TPQD,TNFap) {" fullword ascii
    $s20 = "function whRYG(kleBhe) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}