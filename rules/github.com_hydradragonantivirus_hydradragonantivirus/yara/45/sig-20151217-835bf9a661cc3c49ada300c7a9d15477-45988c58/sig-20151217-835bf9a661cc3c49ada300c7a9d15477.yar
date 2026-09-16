rule sig_20151217_835bf9a661cc3c49ada300c7a9d15477 {
  meta:
    description = "datamaliciousorder - file 20151217_835bf9a661cc3c49ada300c7a9d15477.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ead84ecc9927580cc9cf10fe6fe4042fba3896ab51501f9e04e7b7954fc3f191"

  strings:
    $s1  = ") - 1));while(true){if (PbtVUcNQvoe >= (1438+344)/297){break;}esiNrQgfA[PbtVUcNQvoe]=Math.round((Math.pow(Math.sin(781), 2) + Ma" ascii
    $s2  = "ow(Math.cos(435), 2) - 1)));} esiNrQgfA[PbtVUcNQvoe]++;}PbtVUcNQvoe++;} return gaMCyIYjTlp}" fullword ascii
    $s3  = "function PnVTaSsmwHRNehgUR(HmtDL){gaMCyIYjTlp= '';PbtVUcNQvoe=Math.round((Math.pow(Math.sin(209), 2) + Math.pow(Math.cos(209), 2" ascii
    $s4  = "th.pow(Math.cos(781), 2) - 1)); while(true) { if(esiNrQgfA[PbtVUcNQvoe] > HmtDL[PbtVUcNQvoe].length-(297+30)/327) { break; } if " ascii
    $s5  = "function PnVTaSsmwHRNehgUR(HmtDL){gaMCyIYjTlp= '';PbtVUcNQvoe=Math.round((Math.pow(Math.sin(209), 2) + Math.pow(Math.cos(209), 2" ascii
    $s6  = "function KjAAeNh(EghzcBzBeQsXKZadydvWOXQbrjlnQKJOHwsh) {return !FLkJzTRBynU(mUvwlgmmYohopRg(EghzcBzBeQsXKZadydvWOXQbrjlnQKJOHwsh" ascii
    $s7  = "var G = new Array();G[0]=[];G[0][0]='d';G[0][1]='a';G[0][2]='d';G[0][3]='a';G[0][4]='46';G[0][5]='3d';G[0][6]='42';G[0][7]='14';" ascii
    $s8  = "function KjAAeNh(EghzcBzBeQsXKZadydvWOXQbrjlnQKJOHwsh) {return !FLkJzTRBynU(mUvwlgmmYohopRg(EghzcBzBeQsXKZadydvWOXQbrjlnQKJOHwsh" ascii
    $s9  = "function FLkJzTRBynU(hqDEaOWXUEZLEh) {return isNaN(hqDEaOWXUEZLEh);}" fullword ascii
    $s10 = "function tFSEsQDWgGfhiwixsJDWvuGbdjXrwubYofJIFGadvEtMdqXGMUoIiC(hugaMUoLAxSkg,MAaOpnkSQAdVZo){ return qdyBKGF[TbWbfWqz[GiOgU(hug" ascii
    $s11 = "function kJhEaHTxzjUXjpsov(YtkVkkFIWm,uqKXrgYomM) {return parseInt(YtkVkkFIWm,uqKXrgYomM);}" fullword ascii
    $s12 = "function GiOgU(QVSMXVMaNXq,ZOeYZauWgNnQR,VCmrrkUX){OAFe=kJhEaHTxzjUXjpsov(QVSMXVMaNXq,ZOeYZauWgNnQR);SDGdB=OAFe.toString(VCmrrkU" ascii
    $s13 = "function tFSEsQDWgGfhiwixsJDWvuGbdjXrwubYofJIFGadvEtMdqXGMUoIiC(hugaMUoLAxSkg,MAaOpnkSQAdVZo){ return qdyBKGF[TbWbfWqz[GiOgU(hug" ascii
    $s14 = "function rYhqeLewfFciuvi(psYPtOUPDFQfaEvkG,xHKrGpEgSYdGCYzicujdppMSuLFVZkAjlm,uWtlBygGPYvFkGNEODxBcXWBWNcKScCXsub){eval(psYPtOUP" ascii
    $s15 = "X);return SDGdB;}" fullword ascii
    $s16 = "function GiOgU(QVSMXVMaNXq,ZOeYZauWgNnQR,VCmrrkUX){OAFe=kJhEaHTxzjUXjpsov(QVSMXVMaNXq,ZOeYZauWgNnQR);SDGdB=OAFe.toString(VCmrrkU" ascii
    $s17 = "function mUvwlgmmYohopRg(rSQobVOYFiIvFgffYIU) {return parseFloat(rSQobVOYFiIvFgffYIU);}" fullword ascii
    $s18 = "function M(xNiLeZgponzOZL,VCBXeObvXLaPy,rxxugqcjyzy) {xNiLeZgponzOZL[VCBXeObvXLaPy]=rxxugqcjyzy;}" fullword ascii
    $s19 = "function QbUWxEAlebvr(YjbWdlsAhPnpF) {return isFinite(YjbWdlsAhPnpF);}" fullword ascii
    $s20 = "function rYhqeLewfFciuvi(psYPtOUPDFQfaEvkG,xHKrGpEgSYdGCYzicujdppMSuLFVZkAjlm,uWtlBygGPYvFkGNEODxBcXWBWNcKScCXsub){eval(psYPtOUP" ascii

  condition:
    uint16(0) == 0x6254 and
    8 of them
}