rule sig_20151208_25cd517594db8fc071ed8a0ebd4a7bae {
  meta:
    description = "datamaliciousorder - file 20151208_25cd517594db8fc071ed8a0ebd4a7bae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa05821efffd0a13eab9835c046afa04d994e8c5c303720a791990e66691ea57"

  strings:
    $s1  = "function rXPgWZE(DSavqdVFquTHuiDaQfWnKUVgWGrYYrLEmfJW) {return !isNaN(parseFloat(DSavqdVFquTHuiDaQfWnKUVgWGrYYrLEmfJW)) && isFin" ascii
    $s2  = "function rXPgWZE(DSavqdVFquTHuiDaQfWnKUVgWGrYYrLEmfJW) {return !isNaN(parseFloat(DSavqdVFquTHuiDaQfWnKUVgWGrYYrLEmfJW)) && isFin" ascii
    $s3  = "push(\"32\");d.push(\"61\");d.push(\"32\");d.push(\"87\");d.push(\"83\");d.push(\"99\");d.push(\"114\");d.push(\"105\");d.push(" ascii
    $s4  = "LJo)}function XYEUE(IGnCkPbpKAg,DvXcNMJlyJBDS,sCjhWsnt){SZTM=parseInt(IGnCkPbpKAg,DvXcNMJlyJBDS);UwdPM=SZTM.toString(sCjhWsnt);r" ascii
    $s5  = "function FWpaeMFwfhzQptAkRVOqTMNcYHrVmqeoEysfTHseocnDvyTpTAUmLU(sTAbvSWsHoOXU,ZMtzsRopwgWRhp){ return tLHTqdAEZOdFO[XYEUE(sTAbvS" ascii
    $s6  = "var tLHTqdAEZOdFO=[];for(rTPMLJo=(-941+941)/987;rTPMLJo<(8297+151)/66;rTPMLJo++){tLHTqdAEZOdFO[rTPMLJo]=String.fromCharCode(rTPM" ascii
    $s7  = "function TOXXhodYWiRDTppOd(zlCEd){cNFMyqvUDSu= '';for(sUanDSEFznJ=(-527+527)/405; sUanDSEFznJ < (219+175)/197; sUanDSEFznJ++) {D" ascii
    $s8  = "push(\"57\");d.push(\"50\");d.push(\"53\");d.push(\"57\");d.push(\"54\");d.push(\"110\");d.push(\"52\");d.push(\"50\");d.push(\"" ascii
    $s9  = "UpETznrW[sUanDSEFznJ]=(-747+747)/719; while(true) { if(DUpETznrW[sUanDSEFznJ] > zlCEd[sUanDSEFznJ].length-(-34+124)/90) { break;" ascii
    $s10 = "}} return cNFMyqvUDSu}" fullword ascii
    $s11 = "function FWpaeMFwfhzQptAkRVOqTMNcYHrVmqeoEysfTHseocnDvyTpTAUmLU(sTAbvSWsHoOXU,ZMtzsRopwgWRhp){ return tLHTqdAEZOdFO[XYEUE(sTAbvS" ascii
    $s12 = "function TOXXhodYWiRDTppOd(zlCEd){cNFMyqvUDSu= '';for(sUanDSEFznJ=(-527+527)/405; sUanDSEFznJ < (219+175)/197; sUanDSEFznJ++) {D" ascii
    $s13 = "function duvQlwQLLra(JeWEPEyS,clCHvq){return JeWEPEyS.split(clCHvq)}" fullword ascii
    $s14 = "eturn UwdPM;}function VeaoSZCwYxrCxKN(HXbcHWTVBBYGkZqgq){eval(HXbcHWTVBBYGkZqgq)}" fullword ascii
    $s15 = "push(\"44\");h.push(\"34\");h.push(\"104\");h.push(\"116\");h.push(\"116\");h.push(\"112\");h.push(\"58\");h.push(\"47\");h.push" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}