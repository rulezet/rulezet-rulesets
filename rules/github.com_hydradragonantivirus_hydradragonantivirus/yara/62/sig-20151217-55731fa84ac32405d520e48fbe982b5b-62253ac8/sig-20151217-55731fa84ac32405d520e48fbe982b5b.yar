rule sig_20151217_55731fa84ac32405d520e48fbe982b5b {
  meta:
    description = "datamaliciousorder - file 20151217_55731fa84ac32405d520e48fbe982b5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45546b9598d8dcbd8a7999bb620073a9bc17830081763b9b907a0e4e0bc8f9c6"

  strings:
    $s1  = ") - 1));while(true){if (wyOucksVpGY >= (4601+841)/907){break;}UvWRQxTFk[wyOucksVpGY]=Math.round((Math.pow(Math.sin(186), 2) + Ma" ascii
    $s2  = "th.pow(Math.cos(186), 2) - 1)); while(true) { if(UvWRQxTFk[wyOucksVpGY] > YXYOt[wyOucksVpGY].length-(255+494)/749) { break; } if" ascii
    $s3  = "w(Math.cos(845), 2) - 1)));} UvWRQxTFk[wyOucksVpGY]++;}wyOucksVpGY++;} return erUTLpZoWJD}" fullword ascii
    $s4  = "function AZKkbyhhcWRCFwxGL(YXYOt){erUTLpZoWJD= '';wyOucksVpGY=Math.round((Math.pow(Math.sin(172), 2) + Math.pow(Math.cos(172), 2" ascii
    $s5  = "function AZKkbyhhcWRCFwxGL(YXYOt){erUTLpZoWJD= '';wyOucksVpGY=Math.round((Math.pow(Math.sin(172), 2) + Math.pow(Math.cos(172), 2" ascii
    $s6  = "function fvPDDOSaVABZ(lzjqCOLCMdanG) {return isFinite(lzjqCOLCMdanG);}" fullword ascii
    $s7  = "function X(uFVBqbjFOlecGM,IUTCRunhNIUGv,KQAePNPZjjq) {uFVBqbjFOlecGM[IUTCRunhNIUGv]=KQAePNPZjjq;}" fullword ascii
    $s8  = "function cJjxBFJ(COAemHCsQdZhGKuSJRSLjBAOGoQClhhhJAFj) {return !AjFDQvuVmuT(hULXfXpMprHJEJG(COAemHCsQdZhGKuSJRSLjBAOGoQClhhhJAFj" ascii
    $s9  = "var u = new Array();u[0]=[];u[0][0]='d';u[0][1]='a';u[0][2]='d';u[0][3]='a';u[0][4]='46';u[0][5]='3d';u[0][6]='42';u[0][7]='14';" ascii
    $s10 = "function v(jFnvFlgyYUSn,eSTphiORzWFGZY){jFnvFlgyYUSn.push(eSTphiORzWFGZY);}" fullword ascii
    $s11 = "function avqmjiTVcyOwfMc(TqeXbhKliXaRhSGpe,uPunqzQvXfGZLBBvsFLNSamxYpEeKCGYhF,bRNJdSqeEWKfQJwxHnKfJAJBTOUPZDaRDfg){eval(TqeXbhKl" ascii
    $s12 = "function hULXfXpMprHJEJG(xItIbzWmhRfIXDDQDyt) {return parseFloat(xItIbzWmhRfIXDDQDyt);}" fullword ascii
    $s13 = "P);return uAonl;}" fullword ascii
    $s14 = "function cJjxBFJ(COAemHCsQdZhGKuSJRSLjBAOGoQClhhhJAFj) {return !AjFDQvuVmuT(hULXfXpMprHJEJG(COAemHCsQdZhGKuSJRSLjBAOGoQClhhhJAFj" ascii
    $s15 = "function WpLDUSQAkAbIQwGOR(sblwahmHjp,NoSJoqwwHb) {return parseInt(sblwahmHjp,NoSJoqwwHb);}" fullword ascii
    $s16 = "function AjFDQvuVmuT(jxIoFtLKisQfLJ) {return isNaN(jxIoFtLKisQfLJ);}" fullword ascii
    $s17 = "function zmUMN(fTrmaYXaoIt,mbehuSqXqIUcZ,szeAXqwP){mGBc=WpLDUSQAkAbIQwGOR(fTrmaYXaoIt,mbehuSqXqIUcZ);uAonl=mGBc.toString(szeAXqw" ascii
    $s18 = "function kXBqsClvKLoYplNNuMbAGdsjOoPhzwVOlihmaICwIovIjfxDHtOBuP(IVTYeBkzrVxcZ,sCGzwFzcisYOLy){ return YaQbIhJ[eXKDjUXH[zmUMN(IVT" ascii
    $s19 = "function avqmjiTVcyOwfMc(TqeXbhKliXaRhSGpe,uPunqzQvXfGZLBBvsFLNSamxYpEeKCGYhF,bRNJdSqeEWKfQJwxHnKfJAJBTOUPZDaRDfg){eval(TqeXbhKl" ascii
    $s20 = "function kXBqsClvKLoYplNNuMbAGdsjOoPhzwVOlihmaICwIovIjfxDHtOBuP(IVTYeBkzrVxcZ,sCGzwFzcisYOLy){ return YaQbIhJ[eXKDjUXH[zmUMN(IVT" ascii

  condition:
    uint16(0) == 0x5865 and
    8 of them
}