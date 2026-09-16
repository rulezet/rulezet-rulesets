rule sig_20151210_e772ba6fa8ec0d9b5bbf4ea42fbd6093 {
  meta:
    description = "datamaliciousorder - file 20151210_e772ba6fa8ec0d9b5bbf4ea42fbd6093.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "169e5b9f170018e24b8c72960faf11a002f40a25f0364a8f9320ff511ea9bf37"

  strings:
    $s1  = "function kyrnFFz(cyipqTNWYaVkwpBXeebpvxitlgsrmfQexRrs) {return !isNaN(parseFloat(cyipqTNWYaVkwpBXeebpvxitlgsrmfQexRrs)) && isFin" ascii
    $s2  = "function kyrnFFz(cyipqTNWYaVkwpBXeebpvxitlgsrmfQexRrs) {return !isNaN(parseFloat(cyipqTNWYaVkwpBXeebpvxitlgsrmfQexRrs)) && isFin" ascii
    $s3  = "function pXZVB(aGZNEfODJhF,uYNGZuXxvKOZI,VGaUQtia){gMTU=parseInt(aGZNEfODJhF,uYNGZuXxvKOZI);OxLDf=gMTU.toString(VGaUQtia);return" ascii
    $s4  = "function WDwdNWxDcns(VHjcTPKJ,ZaSDTG){return VHjcTPKJ.split(ZaSDTG)}" fullword ascii
    $s5  = "function LNpPaXHScTxiIzimdtVacLulYHYgULTbtYhthBnsJkVJcktkxHmfui(kTUAfxZoVjWpB,tkkgEFImmhIVYZ){ return oGfJueyVTvtqx[pXZVB(kTUAfx" ascii
    $s6  = "fLAVOKg=(-82+82)/574;while(true){if(fLAVOKg>=(119975+345)/940){break;}oGfJueyVTvtqx[fLAVOKg]=String.fromCharCode(fLAVOKg);fLAVOK" ascii
    $s7  = ";}} return WgxEXQcDaxI}" fullword ascii
    $s8  = "function pXZVB(aGZNEfODJhF,uYNGZuXxvKOZI,VGaUQtia){gMTU=parseInt(aGZNEfODJhF,uYNGZuXxvKOZI);OxLDf=gMTU.toString(VGaUQtia);return" ascii
    $s9  = "function SBRWHgLeaQjrCFQcW(dlHbN){WgxEXQcDaxI= '';for(KIhBWoiRqBH=(-835+835)/473; KIhBWoiRqBH < (1092+52)/572; KIhBWoiRqBH++) {o" ascii
    $s10 = "fLAVOKg=(-82+82)/574;while(true){if(fLAVOKg>=(119975+345)/940){break;}oGfJueyVTvtqx[fLAVOKg]=String.fromCharCode(fLAVOKg);fLAVOK" ascii
    $s11 = "function LNpPaXHScTxiIzimdtVacLulYHYgULTbtYhthBnsJkVJcktkxHmfui(kTUAfxZoVjWpB,tkkgEFImmhIVYZ){ return oGfJueyVTvtqx[pXZVB(kTUAfx" ascii
    $s12 = " OxLDf;}function xcDQnnbgKdPMLqB(XRQFRinSCwxjqdtgX){eval(XRQFRinSCwxjqdtgX)}" fullword ascii
    $s13 = "function SBRWHgLeaQjrCFQcW(dlHbN){WgxEXQcDaxI= '';for(KIhBWoiRqBH=(-835+835)/473; KIhBWoiRqBH < (1092+52)/572; KIhBWoiRqBH++) {o" ascii
    $s14 = "AzVHFGVw[KIhBWoiRqBH]=(-381+381)/836; while(true) { if(oAzVHFGVw[KIhBWoiRqBH] > dlHbN[KIhBWoiRqBH].length-(0+920)/920) { break; " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}