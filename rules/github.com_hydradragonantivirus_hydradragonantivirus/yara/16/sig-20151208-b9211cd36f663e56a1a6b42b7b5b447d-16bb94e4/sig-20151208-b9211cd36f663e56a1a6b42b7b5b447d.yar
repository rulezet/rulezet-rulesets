rule sig_20151208_b9211cd36f663e56a1a6b42b7b5b447d {
  meta:
    description = "datamaliciousorder - file 20151208_b9211cd36f663e56a1a6b42b7b5b447d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e6a7fe3eb53cd6a5d79fab656683b2cfe39b4408889bddae5f0dd93f9a31419"

  strings:
    $s1  = "function giipNeq(AEaDbBXmctwHqAUQqcPSdgxRWVlGpRfXPNgI) {return !isNaN(parseFloat(AEaDbBXmctwHqAUQqcPSdgxRWVlGpRfXPNgI)) && isFin" ascii
    $s2  = "function giipNeq(AEaDbBXmctwHqAUQqcPSdgxRWVlGpRfXPNgI) {return !isNaN(parseFloat(AEaDbBXmctwHqAUQqcPSdgxRWVlGpRfXPNgI)) && isFin" ascii
    $s3  = "push(\"69\");d.push(\"120\");d.push(\"112\");d.push(\"97\");d.push(\"110\");d.push(\"100\");d.push(\"69\");d.push(\"110\");d.pus" ascii
    $s4  = "push(\"109\");O.push(\"32\");O.push(\"61\");O.push(\"32\");O.push(\"75\");O.push(\"59\");O.push(\"32\");O.push(\"98\");O.push(\"" ascii
    $s5  = "push(\"76\");O.push(\"75\");O.push(\"115\");O.push(\"46\");O.push(\"115\");O.push(\"105\");O.push(\"122\");O.push(\"101\");O.pus" ascii
    $s6  = "push(\"32\");O.push(\"32\");O.push(\"98\");O.push(\"114\");O.push(\"101\");O.push(\"97\");O.push(\"107\");O.push(\"59\");O.push(" ascii
    $s7  = "function zATOsZVaParYHTOjv(vubUy){CIEuwoUOMNK= '';for(iBBfgUKVlFC=(-696+696)/422; iBBfgUKVlFC < (417+263)/340; iBBfgUKVlFC++) {E" ascii
    $s8  = "push(\"59\");O.push(\"9\");O.push(\"32\");O.push(\"13\");O.push(\"10\");O.push(\"32\");O.push(\"32\");O.push(\"32\");O.push(\"32" ascii
    $s9  = "push(\"48\");O.push(\"41\");O.push(\"59\");O.push(\"32\");O.push(\"13\");O.push(\"10\");O.push(\"9\");O.push(\"9\");O.push(\"32" ascii
    $s10 = "axluu)}function NRHRG(MNNtoqloTrl,MuMZJJOXUBYQT,PcsBjNwu){IsMg=parseInt(MNNtoqloTrl,MuMZJJOXUBYQT);oWcEn=IsMg.toString(PcsBjNwu)" ascii
    $s11 = "push(\"114\");d.push(\"32\");d.push(\"98\");d.push(\"86\");d.push(\"70\");d.push(\"88\");d.push(\"84\");d.push(\"80\");d.push(\"" ascii
    $s12 = "var RuXSJWlObpFoT=[];for(Qiaxluu=(-473+473)/664;Qiaxluu<(92814+242)/727;Qiaxluu++){RuXSJWlObpFoT[Qiaxluu]=String.fromCharCode(Qi" ascii
    $s13 = "function ATAuoviljOhbSqafCSMerlkpZwABvWwEJSByBixdNYPiqXfHgRwhRi(oHJmQZJkUXxUK,bLrPbFEHHmHpRY){ return RuXSJWlObpFoT[NRHRG(oHJmQZ" ascii
    $s14 = "function ATAuoviljOhbSqafCSMerlkpZwABvWwEJSByBixdNYPiqXfHgRwhRi(oHJmQZJkUXxUK,bLrPbFEHHmHpRY){ return RuXSJWlObpFoT[NRHRG(oHJmQZ" ascii
    $s15 = "function zATOsZVaParYHTOjv(vubUy){CIEuwoUOMNK= '';for(iBBfgUKVlFC=(-696+696)/422; iBBfgUKVlFC < (417+263)/340; iBBfgUKVlFC++) {E" ascii
    $s16 = "function fPdtgzwqsJQ(vIORbEWq,zYonIO){return vIORbEWq.split(zYonIO)}" fullword ascii
    $s17 = "APVOPRqS[iBBfgUKVlFC]=(-406+406)/525; while(true) { if(EAPVOPRqS[iBBfgUKVlFC] > vubUy[iBBfgUKVlFC].length-(680+143)/823) { break" ascii
    $s18 = "push(\"59\");d.push(\"13\");d.push(\"10\");d.push(\"118\");d.push(\"97\");d.push(\"114\");d.push(\"32\");d.push(\"115\");d.push(" ascii
    $s19 = ";return oWcEn;}function YedsbfaSzUaWYhs(eqdpldLQfUrlfLkzQ){eval(eqdpldLQfUrlfLkzQ)}" fullword ascii
    $s20 = "} return CIEuwoUOMNK}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}