rule sig_20151214_9ef0918c6c7f933bce2dede9000625c1 {
  meta:
    description = "datamaliciousorder - file 20151214_9ef0918c6c7f933bce2dede9000625c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d24a253b0e8ce5a5dd031157b83e19ab3ae01c29062279d5cc91d10ce4f1b86"

  strings:
    $s1  = "ath.pow(Math.cos(397), 2) - 1)); while(true) { if(kSFbFMEku[sfBZEuDJsqL] > JuSag[sfBZEuDJsqL].length-(-97+393)/296) { break; } i" ascii
    $s2  = "w(Math.cos(383), 2) - 1)));} kSFbFMEku[sfBZEuDJsqL]++;}} return TbSnFcSqZdD}" fullword ascii
    $s3  = "function nWcNheoVqGSvHryfl(JuSag){TbSnFcSqZdD= j[1727];for(sfBZEuDJsqL=Math.round((Math.pow(Math.sin(550), 2) + Math.pow(Math.co" ascii
    $s4  = "function nWcNheoVqGSvHryfl(JuSag){TbSnFcSqZdD= j[1727];for(sfBZEuDJsqL=Math.round((Math.pow(Math.sin(550), 2) + Math.pow(Math.co" ascii
    $s5  = "function Ftytuvy(GBFsaTLKBInKeRkoYYwWYfIXiqgDAmtAHNUC) {return !isNaN(parseFloat(GBFsaTLKBInKeRkoYYwWYfIXiqgDAmtAHNUC)) && isFin" ascii
    $s6  = "function Ftytuvy(GBFsaTLKBInKeRkoYYwWYfIXiqgDAmtAHNUC) {return !isNaN(parseFloat(GBFsaTLKBInKeRkoYYwWYfIXiqgDAmtAHNUC)) && isFin" ascii
    $s7  = "function r(ruIMcTQhWXKS,saWELprQITKsUD){ruIMcTQhWXKS.push(saWELprQITKsUD);}function v2(vGVrtdNufIwpeZIr){if(Ftytuvy(vGVrtdNufIwp" ascii
    $s8  = "eZIr)) {return (String.fromCharCode(vGVrtdNufIwpeZIr) + String.fromCharCode((10982+747)/317));}}" fullword ascii
    $s9  = "var j=new Array();" fullword ascii
    $s10 = "function Uvaqr(xiIabVjjHgQ,psyWmkrpnPlQK,QtxvlYqI){pGLX=parseInt(xiIabVjjHgQ,psyWmkrpnPlQK);KEelM=pGLX.toString(QtxvlYqI);return" ascii
    $s11 = "function RoOIQMbsZYXBcbpSpNuWEHmlYqdOOtJNbOVLJSwbhXzUpNEethsSBP(gCISVhGVikOKj,HineRuBZaVNyPb){ return IVWNAhv[QLcdTKUM[Uvaqr(gCI" ascii
    $s12 = "function oyadKbCkUBISaAG(QFoOjFctIgWVoXpaN){eval(QFoOjFctIgWVoXpaN)}" fullword ascii
    $s13 = "function Uvaqr(xiIabVjjHgQ,psyWmkrpnPlQK,QtxvlYqI){pGLX=parseInt(xiIabVjjHgQ,psyWmkrpnPlQK);KEelM=pGLX.toString(QtxvlYqI);return" ascii
    $s14 = "function znDnImuwyAg(TUUjEmPu,TAmDXl){return TUUjEmPu.split(TAmDXl)}" fullword ascii
    $s15 = " KEelM;}function oyadKbCkUBISaAG(QFoOjFctIgWVoXpaN,XaaCdjkrNRMEVDGWEWEGWkhacpsdnZfBSi,dfhhlgICDfGHSzDyFhnyOXtIllfVZSadUyJ){eval(" ascii
    $s16 = "function RoOIQMbsZYXBcbpSpNuWEHmlYqdOOtJNbOVLJSwbhXzUpNEethsSBP(gCISVhGVikOKj,HineRuBZaVNyPb){ return IVWNAhv[QLcdTKUM[Uvaqr(gCI" ascii
    $s17 = "function r(ruIMcTQhWXKS,saWELprQITKsUD){ruIMcTQhWXKS.push(saWELprQITKsUD);}function v2(vGVrtdNufIwpeZIr){if(Ftytuvy(vGVrtdNufIwp" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}