rule sig_20151209_d71b8baa5c9aecc79281dffd5516f510 {
  meta:
    description = "datamaliciousorder - file 20151209_d71b8baa5c9aecc79281dffd5516f510.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "312884cbe065d64ed3cc24acdef560a8a81d14af25e716470df5cd4fd6320686"

  strings:
    $s1  = "function eXauWMlPYSf(SfJoilNR,wQoTJr){return SfJoilNR.split(wQoTJr)}" fullword ascii
    $s2  = "function kmUNC(XmLTsmMKtxs,wJHUybNRknhRw,UYxaZldN){CrvG=parseInt(XmLTsmMKtxs,wJHUybNRknhRw);baTgc=CrvG.toString(UYxaZldN);return" ascii
    $s3  = " baTgc;}function INTnDKXdraZOWPH(aDpPBVCxMvJUfoEAy){eval(aDpPBVCxMvJUfoEAy)}" fullword ascii
    $s4  = "function kmUNC(XmLTsmMKtxs,wJHUybNRknhRw,UYxaZldN){CrvG=parseInt(XmLTsmMKtxs,wJHUybNRknhRw);baTgc=CrvG.toString(UYxaZldN);return" ascii
    $s5  = "return JotKaCDoNBd}" fullword ascii
    $s6  = "SCIGMN[TCguOVUHLeY]=(-142+142)/65; while(true) { if(goWSCIGMN[TCguOVUHLeY] > qysOa[TCguOVUHLeY].length-(200+19)/219) { break; } " ascii
    $s7  = "function LCFgGmIJCznXKldME(qysOa){JotKaCDoNBd= '';for(TCguOVUHLeY=(-758+758)/99; TCguOVUHLeY < (1074+4)/539; TCguOVUHLeY++) {goW" ascii
    $s8  = "function ZOvNgha(PwtCacUcytvHtULxrOmGNEvjwMenYSDRlXWK) {return !isNaN(parseFloat(PwtCacUcytvHtULxrOmGNEvjwMenYSDRlXWK)) && isFin" ascii
    $s9  = "function ZOvNgha(PwtCacUcytvHtULxrOmGNEvjwMenYSDRlXWK) {return !isNaN(parseFloat(PwtCacUcytvHtULxrOmGNEvjwMenYSDRlXWK)) && isFin" ascii
    $s10 = "function LCFgGmIJCznXKldME(qysOa){JotKaCDoNBd= '';for(TCguOVUHLeY=(-758+758)/99; TCguOVUHLeY < (1074+4)/539; TCguOVUHLeY++) {goW" ascii
    $s11 = "function aqoRWxaGUvyQVxvIfKwBQWTozjsbsXlzzohBGWchcaNKotQGSFTmRV(YdmLMmyAzoxmW,CtbrdkrsptXSOF){ return DDPTo[kmUNC(YdmLMmyAzoxmW[" ascii
    $s12 = "function aqoRWxaGUvyQVxvIfKwBQWTozjsbsXlzzohBGWchcaNKotQGSFTmRV(YdmLMmyAzoxmW,CtbrdkrsptXSOF){ return DDPTo[kmUNC(YdmLMmyAzoxmW[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}