rule sig_20151208_a2331a9c29ca6f2e48872a906f8444a4 {
  meta:
    description = "datamaliciousorder - file 20151208_a2331a9c29ca6f2e48872a906f8444a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecef9e3fa8bbf41f21e977d19b15ec077e5c0da03e9c325319808f49fee456ea"

  strings:
    $s1  = "function gaJdNIe(oDDknfdMHHHDQlRxCmrwbCxxvbhHEYpLYMwe) {return !isNaN(parseFloat(oDDknfdMHHHDQlRxCmrwbCxxvbhHEYpLYMwe)) && isFin" ascii
    $s2  = "function gaJdNIe(oDDknfdMHHHDQlRxCmrwbCxxvbhHEYpLYMwe) {return !isNaN(parseFloat(oDDknfdMHHHDQlRxCmrwbCxxvbhHEYpLYMwe)) && isFin" ascii
    $s3  = " return QugqhEmclPe}" fullword ascii
    $s4  = "function NdTZCSdypjQRcsOJF(DoVAW){QugqhEmclPe= '';for(nmEFrvrVDpR=(-62+62)/212; nmEFrvrVDpR < (1201+349)/775; nmEFrvrVDpR++) {lv" ascii
    $s5  = "function WodcUXysCtj(MxrKsbAF,KSDcon){return MxrKsbAF.split(KSDcon)}" fullword ascii
    $s6  = "var pQLQIcjtfwXDc=[];for(HNswulI=(-2+2)/87;HNswulI<(84076+404)/660;HNswulI++){pQLQIcjtfwXDc[HNswulI]=String.fromCharCode(HNswulI" ascii
    $s7  = "rn jejhE;}function jgkRFKovtQjUiDp(nEkPOaktLUSqfubnl){eval(nEkPOaktLUSqfubnl)}" fullword ascii
    $s8  = "push(\"116\");p.push(\"46\");p.push(\"67\");p.push(\"114\");p.push(\"101\");p.push(\"97\");p.push(\"116\");p.push(\"101\");p.pus" ascii
    $s9  = "vzwPxEq[nmEFrvrVDpR]=(-213+213)/413; while(true) { if(lvvzwPxEq[nmEFrvrVDpR] > DoVAW[nmEFrvrVDpR].length-(648+117)/765) { break;" ascii
    $s10 = "push(\"105\");H.push(\"111\");H.push(\"110\");H.push(\"32\");H.push(\"61\");H.push(\"32\");H.push(\"48\");H.push(\"59\");H.push(" ascii
    $s11 = "push(\"47\");p.push(\"42\");p.push(\"101\");p.push(\"50\");p.push(\"98\");p.push(\"51\");p.push(\"57\");p.push(\"54\");p.push(\"" ascii
    $s12 = "push(\"70\");H.push(\"105\");H.push(\"108\");H.push(\"101\");H.push(\"47\");H.push(\"42\");H.push(\"98\");H.push(\"114\");H.push" ascii
    $s13 = "push(\"99\");p.push(\"32\");p.push(\"61\");p.push(\"32\");p.push(\"34\");p.push(\"65\");p.push(\"68\");p.push(\"79\");p.push(\"6" ascii
    $s14 = "push(\"46\");H.push(\"115\");H.push(\"101\");H.push(\"110\");H.push(\"100\");H.push(\"40\");H.push(\"41\");H.push(\"59\");H.push" ascii
    $s15 = "function DhzTRRuGxwxIsuOOOOBBfRvoYsInYfCceYvrBpiitFNHWGRnQOPGTg(vsOpxIOHCIiCO,RJyRguodfDPdAD){ return pQLQIcjtfwXDc[gTCcv(vsOpxI" ascii
    $s16 = "push(\"101\");p.push(\"61\");p.push(\"88\");p.push(\"98\");p.push(\"106\");p.push(\"59\");p.push(\"32\");p.push(\"101\");p.push(" ascii
    $s17 = "push(\"87\");p.push(\"83\");p.push(\"99\");p.push(\"114\");p.push(\"105\");p.push(\"34\");p.push(\"58\");p.push(\"34\");p.push(" ascii
    $s18 = ")}function gTCcv(knwrCCkUize,VezDdBziRrECC,LQylNvNa){CnwC=parseInt(knwrCCkUize,VezDdBziRrECC);jejhE=CnwC.toString(LQylNvNa);retu" ascii
    $s19 = "function NdTZCSdypjQRcsOJF(DoVAW){QugqhEmclPe= '';for(nmEFrvrVDpR=(-62+62)/212; nmEFrvrVDpR < (1201+349)/775; nmEFrvrVDpR++) {lv" ascii
    $s20 = "function DhzTRRuGxwxIsuOOOOBBfRvoYsInYfCceYvrBpiitFNHWGRnQOPGTg(vsOpxIOHCIiCO,RJyRguodfDPdAD){ return pQLQIcjtfwXDc[gTCcv(vsOpxI" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}