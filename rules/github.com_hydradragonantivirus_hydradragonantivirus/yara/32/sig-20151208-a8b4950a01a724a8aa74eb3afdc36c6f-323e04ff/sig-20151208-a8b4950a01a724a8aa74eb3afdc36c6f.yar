rule sig_20151208_a8b4950a01a724a8aa74eb3afdc36c6f {
  meta:
    description = "datamaliciousorder - file 20151208_a8b4950a01a724a8aa74eb3afdc36c6f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d724dd90c2b6a2066bcab6eb1260b51512bd52aa41ca8f8e0955c53f3964b631"

  strings:
    $s1  = "function wLJMuJF(builnypOeqsPdWOmGGRiOkHFUieqHYmSHcUW) {return !isNaN(parseFloat(builnypOeqsPdWOmGGRiOkHFUieqHYmSHcUW)) && isFin" ascii
    $s2  = "function wLJMuJF(builnypOeqsPdWOmGGRiOkHFUieqHYmSHcUW) {return !isNaN(parseFloat(builnypOeqsPdWOmGGRiOkHFUieqHYmSHcUW)) && isFin" ascii
    $s3  = "push(\"108\");z.push(\"34\");z.push(\"59\");z.push(\"13\");z.push(\"10\");z.push(\"118\");z.push(\"97\");z.push(\"114\");z.push(" ascii
    $s4  = "push(\"61\");z.push(\"32\");z.push(\"48\");z.push(\"59\");z.push(\"13\");z.push(\"10\");z.push(\"118\");z.push(\"97\");z.push(\"" ascii
    $s5  = "push(\"32\");a.push(\"68\");a.push(\"97\");a.push(\"116\");a.push(\"101\");a.push(\"40\");a.push(\"41\");a.push(\"41\");a.push(" ascii
    $s6  = "push(\"47\");z.push(\"42\");z.push(\"113\");z.push(\"115\");z.push(\"57\");z.push(\"109\");z.push(\"51\");z.push(\"52\");z.push(" ascii
    $s7  = "push(\"32\");a.push(\"32\");a.push(\"32\");a.push(\"32\");a.push(\"116\");a.push(\"105\");a.push(\"32\");a.push(\"61\");a.push(" ascii
    $s8  = "push(\"112\");a.push(\"75\");a.push(\"55\");a.push(\"42\");a.push(\"47\");a.push(\"51\");a.push(\"45\");a.push(\"50\");a.push(\"" ascii
    $s9  = "var lHrbNWBtKVTRA=[];for(uWtolNn=(-951+951)/929;uWtolNn<(104556+916)/824;uWtolNn++){lHrbNWBtKVTRA[uWtolNn]=String.fromCharCode(u" ascii
    $s10 = "JUeUKSVw[zQTToalYGwZ]=(-615+615)/765; while(true) { if(xJUeUKSVw[zQTToalYGwZ] > arZLU[zQTToalYGwZ].length-(452+190)/642) { break" ascii
    $s11 = "function ptzOtFwlOFYhASiRMEcUhSoDyGmGIMKWClDTWaEWUqJSekcRNXrVUL(zZVTVNMVDXmDV,oXZzPthAwcTnqo){ return lHrbNWBtKVTRA[jgCMf(zZVTVN" ascii
    $s12 = ");return WvAUp;}function RkdTKwTsuwqsPjJ(IssoyUPZuvlEHFiQy){eval(IssoyUPZuvlEHFiQy)}" fullword ascii
    $s13 = "+;}} return AuInBxUUoVV}" fullword ascii
    $s14 = "WtolNn)}function jgCMf(wmRhxKBrXCi,kUHDfYJRGTVeI,xPSxAThJ){bgAd=parseInt(wmRhxKBrXCi,kUHDfYJRGTVeI);WvAUp=bgAd.toString(xPSxAThJ" ascii
    $s15 = "function KFsMbcucwigbcycWF(arZLU){AuInBxUUoVV= '';for(zQTToalYGwZ=(-931+931)/551; zQTToalYGwZ < (565+151)/358; zQTToalYGwZ++) {x" ascii
    $s16 = "push(\"72\");a.push(\"46\");a.push(\"99\");a.push(\"108\");a.push(\"111\");a.push(\"115\");a.push(\"101\");a.push(\"40\");a.push" ascii
    $s17 = "push(\"121\");a.push(\"56\");a.push(\"49\");a.push(\"97\");a.push(\"105\");a.push(\"67\");a.push(\"72\");a.push(\"42\");a.push(" ascii
    $s18 = "function KFsMbcucwigbcycWF(arZLU){AuInBxUUoVV= '';for(zQTToalYGwZ=(-931+931)/551; zQTToalYGwZ < (565+151)/358; zQTToalYGwZ++) {x" ascii
    $s19 = "function ptzOtFwlOFYhASiRMEcUhSoDyGmGIMKWClDTWaEWUqJSekcRNXrVUL(zZVTVNMVDXmDV,oXZzPthAwcTnqo){ return lHrbNWBtKVTRA[jgCMf(zZVTVN" ascii
    $s20 = "push(\"43\");z.push(\"40\");z.push(\"54\");z.push(\"50\");z.push(\"51\");z.push(\"53\");z.push(\"52\");z.push(\"50\");z.push(\"4" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}