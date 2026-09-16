rule sig_20160411_0f0c0e51a3795635041e970ff31bdefa {
  meta:
    description = "datamaliciousorder - file 20160411_0f0c0e51a3795635041e970ff31bdefa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d10ef43623498655ffb78e4fd91b910cc241fb15c38a77939f7e039e83e9366"

  strings:
    $s1  = "var rp = true  , ZlSO = vft[7] + vft[9] + vft[11];" fullword ascii
    $s2  = "return TRHDHHo[0] + TRHDHHo[2] + TRHDHHo[4] + \".F\" + TRHDHHo[7] + TRHDHHo[9] + TRHDHHo[12] + TRHDHHo[14];" fullword ascii
    $s3  = "var vft = (\"2.XMLHTTP QBbHNkc YtAoi XML ream St lFdkEKwU AD qPOUXvk O VndL D\").split(\" \");" fullword ascii
    $s4  = "aekA.open(Hosil,iVINF,false);" fullword ascii
    $s5  = "if(K>=z.length) {break;}" fullword ascii
    $s6  = "function MfxP(UNIeY) {" fullword ascii
    $s7  = "return aclXc.status;" fullword ascii
    $s8  = "function lpobZ(TwwSlL) {" fullword ascii
    $s9  = "function gPMMRYr(kNfb,Ugfqc) {" fullword ascii
    $s10 = "return new ActiveXObject(DmZz);" fullword ascii
    $s11 = "function axsfuMr(zPdP) {" fullword ascii
    $s12 = "return QfthBmu[0];" fullword ascii
    $s13 = "if (e >= bNNri.length) {break;}" fullword ascii
    $s14 = "function MXMS(LdOVv) {" fullword ascii
    $s15 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s16 = "if (LdOVv > 155795-221){return true;} else {return false;}" fullword ascii
    $s17 = "function DYYAcxjz(Kfd) {" fullword ascii
    $s18 = "function NXOV(GcZvq,ENarn) {" fullword ascii
    $s19 = "function tAuImJtXz(dyuRu) {" fullword ascii
    $s20 = "function saDaa(tCLYLi) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}