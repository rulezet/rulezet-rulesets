rule sig_20160419_0e1d30cbb269fabd5a15e46e5c38e129 {
  meta:
    description = "datamaliciousorder - file 20160419_0e1d30cbb269fabd5a15e46e5c38e129.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4dbf6cee1bc65504ce1be30e16ece721a86cb6203bfc8bc8ed41677edc6c5d80"

  strings:
    $s1  = "var iy = true  , UFmn = znz[7] + znz[9] + znz[11];" fullword ascii
    $s2  = "return CcqZsVK[0] + CcqZsVK[2] + CcqZsVK[4] + \".F\" + CcqZsVK[7] + CcqZsVK[9] + CcqZsVK[12] + CcqZsVK[14];" fullword ascii
    $s3  = "var znz = (\"2.XMLHTTP kmlxCJe RpszL XML ream St YntoREEa AD xqPHpsP O RzDW D\").split(\" \");" fullword ascii
    $s4  = "IRkK.open(elxmE,gVRaR,false);" fullword ascii
    $s5  = "if(j>=s.length) {break;}" fullword ascii
    $s6  = "function HNqtwVaa(Etwy) {" fullword ascii
    $s7  = "function GpDCM(WeDrXfNX,mfCQ) {" fullword ascii
    $s8  = "return \"OgpyqKjqnLOOiz\";" fullword ascii
    $s9  = "return new ActiveXObject(ClCN);" fullword ascii
    $s10 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s11 = "function TrDiEL(wBpqlju) {" fullword ascii
    $s12 = "function uqpR(eEmEL,gVRaR,elxmE) {" fullword ascii
    $s13 = "function sRgp(lVFfD) {" fullword ascii
    $s14 = "TOA = j; break; " fullword ascii
    $s15 = "if (J >= mcNOa.length) {break;}" fullword ascii
    $s16 = "function XiRYA(BBjdJk) {" fullword ascii
    $s17 = "if (UCycB != 392-192){return false;} else {return true;}" fullword ascii
    $s18 = "if (iEuWv > 191716-425){return true;} else {return false;}" fullword ascii
    $s19 = "function hufU(mcNOa) {" fullword ascii
    $s20 = "function DgtXnRyjC(tcppWVvfWwK) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}