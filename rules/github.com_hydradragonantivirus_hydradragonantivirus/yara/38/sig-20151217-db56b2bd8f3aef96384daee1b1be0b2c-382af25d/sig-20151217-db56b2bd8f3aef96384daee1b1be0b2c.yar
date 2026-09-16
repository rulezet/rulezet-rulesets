rule sig_20151217_db56b2bd8f3aef96384daee1b1be0b2c {
  meta:
    description = "datamaliciousorder - file 20151217_db56b2bd8f3aef96384daee1b1be0b2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "973a72517e9cfb07a5ab3086f83a76334be80a33e29f18e28e14a77862224b49"

  strings:
    $s1  = "th.pow(Math.cos(716), 2) - 1)); while(true) { if(JYQcpXcIe[COrJXcjplRH] > UObOV[COrJXcjplRH].length-(-702+747)/45) { break; } if" ascii
    $s2  = "function tTnDwwmRkqiORABpu(UObOV){VOWZLVBxNYZ= '';COrJXcjplRH=Math.round((Math.pow(Math.sin(880), 2) + Math.pow(Math.cos(880), 2" ascii
    $s3  = "ow(Math.cos(254), 2) - 1)));} JYQcpXcIe[COrJXcjplRH]++;}COrJXcjplRH++;} return VOWZLVBxNYZ}" fullword ascii
    $s4  = ") - 1));while(true){if (COrJXcjplRH >= (2282+388)/445){break;}JYQcpXcIe[COrJXcjplRH]=Math.round((Math.pow(Math.sin(716), 2) + Ma" ascii
    $s5  = "function wmKryUL(LTOlpFPJTnlhUGbHwBaMrqqPezgsEGMmCDtr) {return !AKFtpuTBBIe(kGPBAANEtcKWbot(LTOlpFPJTnlhUGbHwBaMrqqPezgsEGMmCDtr" ascii
    $s6  = "function tTnDwwmRkqiORABpu(UObOV){VOWZLVBxNYZ= '';COrJXcjplRH=Math.round((Math.pow(Math.sin(880), 2) + Math.pow(Math.cos(880), 2" ascii
    $s7  = "function tibJOGjUPpUuoANwE(kdTloGzEgf,vIsPduCNjS) {return parseInt(kdTloGzEgf,vIsPduCNjS);}" fullword ascii
    $s8  = "function AKFtpuTBBIe(sJvfrTGDdKyqdl) {return isNaN(sJvfrTGDdKyqdl);}" fullword ascii
    $s9  = "function wmKryUL(LTOlpFPJTnlhUGbHwBaMrqqPezgsEGMmCDtr) {return !AKFtpuTBBIe(kGPBAANEtcKWbot(LTOlpFPJTnlhUGbHwBaMrqqPezgsEGMmCDtr" ascii
    $s10 = "var D = new Array();D[0]=[];D[0][0]='d';D[0][1]='a';D[0][2]='d';D[0][3]='a';D[0][4]='46';D[0][5]='3d';D[0][6]='42';D[0][7]='14';" ascii
    $s11 = "function TbsUVQqeSghxEhQ(kKcrmPjgQBsHjZqNY,XYSQBtCEDdNLNieCZIpXzCVQKCDuvBxkma,QHZSVKxkzPZnlhqlsrtnDdjwWYIBtQKkRUT){eval(kKcrmPjg" ascii
    $s12 = "function YXqKy(vZbvftxAoce,QdXKeztSMZPTV,AAbUkWTK){BwQg=tibJOGjUPpUuoANwE(vZbvftxAoce,QdXKeztSMZPTV);hNfuj=BwQg.toString(AAbUkWT" ascii
    $s13 = "function i(LXqfQkTaaqpQ,ciqtndWFMpIyzJ){LXqfQkTaaqpQ.push(ciqtndWFMpIyzJ);}" fullword ascii
    $s14 = "function NtdHbUNVdyIAeLlrCTCIYpbnBdwiCYMoMoYngCxWHVROHwoDryBFlj(aOgRXxsSEuRHz,SUKSCtZlqtiNyb){ return FAgPNai[PCrhTqDx[YXqKy(aOg" ascii
    $s15 = "var D = new Array();D[0]=[];D[0][0]='d';D[0][1]='a';D[0][2]='d';D[0][3]='a';D[0][4]='46';D[0][5]='3d';D[0][6]='42';D[0][7]='14';" ascii
    $s16 = "function TbsUVQqeSghxEhQ(kKcrmPjgQBsHjZqNY,XYSQBtCEDdNLNieCZIpXzCVQKCDuvBxkma,QHZSVKxkzPZnlhqlsrtnDdjwWYIBtQKkRUT){eval(kKcrmPjg" ascii
    $s17 = "function ZJSDgZdXpLEA(rdZYaaKSaVYNY) {return isFinite(rdZYaaKSaVYNY);}" fullword ascii
    $s18 = "K);return hNfuj;}" fullword ascii
    $s19 = "function NtdHbUNVdyIAeLlrCTCIYpbnBdwiCYMoMoYngCxWHVROHwoDryBFlj(aOgRXxsSEuRHz,SUKSCtZlqtiNyb){ return FAgPNai[PCrhTqDx[YXqKy(aOg" ascii
    $s20 = "function YXqKy(vZbvftxAoce,QdXKeztSMZPTV,AAbUkWTK){BwQg=tibJOGjUPpUuoANwE(vZbvftxAoce,QdXKeztSMZPTV);hNfuj=BwQg.toString(AAbUkWT" ascii

  condition:
    uint16(0) == 0x4350 and
    8 of them
}