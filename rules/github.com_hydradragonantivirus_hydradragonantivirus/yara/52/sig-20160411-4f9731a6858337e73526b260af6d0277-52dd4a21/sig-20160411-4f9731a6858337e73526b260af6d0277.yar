rule sig_20160411_4f9731a6858337e73526b260af6d0277 {
  meta:
    description = "datamaliciousorder - file 20160411_4f9731a6858337e73526b260af6d0277.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7eec6a06da344db5fa5179eb7d19ad531596c72b73a724a1ecdfaa7837c66db9"

  strings:
    $s1  = "return FQrLQkq[0] + FQrLQkq[2] + FQrLQkq[4] + \".F\" + FQrLQkq[7] + FQrLQkq[9] + FQrLQkq[12] + FQrLQkq[14];" fullword ascii
    $s2  = "var bS = true  , iVvM = ZoT[7] + ZoT[9] + ZoT[11];" fullword ascii
    $s3  = "var ZoT = (\"2.XMLHTTP jMbwonf XsxEe XML ream St MCOHeSgs AD LFoecWR O qmTM D\").split(\" \");" fullword ascii
    $s4  = "URXz.open(rGFYG,otkcf,false);" fullword ascii
    $s5  = "return zKfKimp[0];" fullword ascii
    $s6  = "function cdbzH(oAzDPL) {" fullword ascii
    $s7  = "function ERLckMt(IHDH,Ysouw) {" fullword ascii
    $s8  = "function mzQz(hKJEe) {" fullword ascii
    $s9  = "function GqzA(plUCj) {" fullword ascii
    $s10 = "return hKJEe.status;" fullword ascii
    $s11 = "if (k >= OAkaL.length) {break;}" fullword ascii
    $s12 = "if(e>=N.length) {break;}" fullword ascii
    $s13 = "function lQFZ(TYukl) {" fullword ascii
    $s14 = "return yDx.size;" fullword ascii
    $s15 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s16 = "function lhPCxOSCU(kNGepdjWipP) {" fullword ascii
    $s17 = "function orvFNoSn(yDx) {" fullword ascii
    $s18 = "return AeOnz;" fullword ascii
    $s19 = "function sOkxB(fAIpVGdb,WxhO) {" fullword ascii
    $s20 = "return aWxjvZq;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}