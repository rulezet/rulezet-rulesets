rule sig_20160419_f041a3d8e639c149311be5f27349d708 {
  meta:
    description = "datamaliciousorder - file 20160419_f041a3d8e639c149311be5f27349d708.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b5a72c3b57cf77a983f507098e4b0061b886b966c66b67f177c075cd574d1ed"

  strings:
    $s1  = "var UF = true  , fqsr = LQP[7] + LQP[9] + LQP[11];" fullword ascii
    $s2  = "return fSlWbDx[0] + fSlWbDx[2] + fSlWbDx[4] + \".F\" + fSlWbDx[7] + fSlWbDx[9] + fSlWbDx[12] + fSlWbDx[14];" fullword ascii
    $s3  = "swpr.open(cMhZv,MzRsC,false);" fullword ascii
    $s4  = "var LQP = (\"2.XMLHTTP OtJNiBT regce XML ream St XDvjilOm AD lolxRnv O Laon D\").split(\" \");" fullword ascii
    $s5  = "if(L>=o.length) {break;}" fullword ascii
    $s6  = "return \"dblMlwVnWXOyhn\";" fullword ascii
    $s7  = "function sKZf(xcQOQ) {" fullword ascii
    $s8  = "return GQhOw;" fullword ascii
    $s9  = "function KqpJU(BXIetKQH,THNr) {" fullword ascii
    $s10 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s11 = "return FvEjc.status;" fullword ascii
    $s12 = "if (qHXOM != 961-761){return false;} else {return true;}" fullword ascii
    $s13 = "function wVIsIvjjU(msbSLhacwit) {" fullword ascii
    $s14 = "return PbyeRa[ZkYs[863-863]]=402-402;" fullword ascii
    $s15 = "function cdpyRg(AJAI,aQqaNE) {" fullword ascii
    $s16 = "function AyTPcDS(WTbQ,CfFOm) {" fullword ascii
    $s17 = "function NQtyv(PbyeRa) {" fullword ascii
    $s18 = "function AUMq(dulhh,tUAjj) {" fullword ascii
    $s19 = "function PJWR(qHXOM) {" fullword ascii
    $s20 = "return aFAt[CGJKxWw[0]+CGJKxWw[1]];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}