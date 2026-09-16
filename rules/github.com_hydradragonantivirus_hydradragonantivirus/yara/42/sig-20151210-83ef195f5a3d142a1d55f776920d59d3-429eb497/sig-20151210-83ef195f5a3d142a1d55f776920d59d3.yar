rule sig_20151210_83ef195f5a3d142a1d55f776920d59d3 {
  meta:
    description = "datamaliciousorder - file 20151210_83ef195f5a3d142a1d55f776920d59d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d4c2bf08f290d91a00e62c05cac94dc4d360c07efe24719faf2e0f9de3eb713"

  strings:
    $s1  = "function QXysrES(VMCSGTzMKCIRryAEMhZEDdMmQCZMIIeKRLef) {return !isNaN(parseFloat(VMCSGTzMKCIRryAEMhZEDdMmQCZMIIeKRLef)) && isFin" ascii
    $s2  = "function QXysrES(VMCSGTzMKCIRryAEMhZEDdMmQCZMIIeKRLef) {return !isNaN(parseFloat(VMCSGTzMKCIRryAEMhZEDdMmQCZMIIeKRLef)) && isFin" ascii
    $s3  = "raTuuHR=(-697+697)/505;while(true){if(raTuuHR>=(26282+86)/206){break;}yxpmPcmwRtNRS[raTuuHR]=String.fromCharCode(raTuuHR);raTuuH" ascii
    $s4  = " return MeXawXgnKuj}" fullword ascii
    $s5  = "function qtlTPLPNmdb(iqAdXkYe,TeKndg){return iqAdXkYe.split(TeKndg)}" fullword ascii
    $s6  = "function fCOgOKzuivSsWPVFYirgIMSlQxMjqeXRzkiorHxCtnNJNwSpbuypOU(lFFsuzVAvFuTR,qBCLzHUfNiAILW){ return yxpmPcmwRtNRS[nirAV(lFFsuz" ascii
    $s7  = "function fCOgOKzuivSsWPVFYirgIMSlQxMjqeXRzkiorHxCtnNJNwSpbuypOU(lFFsuzVAvFuTR,qBCLzHUfNiAILW){ return yxpmPcmwRtNRS[nirAV(lFFsuz" ascii
    $s8  = "unbMMqf[dcDTOooitnc]=(-717+717)/843; while(true) { if(oyunbMMqf[dcDTOooitnc] > eTBdW[dcDTOooitnc].length-(14+12)/26) { break; } " ascii
    $s9  = "raTuuHR=(-697+697)/505;while(true){if(raTuuHR>=(26282+86)/206){break;}yxpmPcmwRtNRS[raTuuHR]=String.fromCharCode(raTuuHR);raTuuH" ascii
    $s10 = "function nirAV(EfecBpPFndC,NSBWXLWpjSyec,TCgPfldk){LzQX=parseInt(EfecBpPFndC,NSBWXLWpjSyec);SObzF=LzQX.toString(TCgPfldk);return" ascii
    $s11 = "function nirAV(EfecBpPFndC,NSBWXLWpjSyec,TCgPfldk){LzQX=parseInt(EfecBpPFndC,NSBWXLWpjSyec);SObzF=LzQX.toString(TCgPfldk);return" ascii
    $s12 = "function YdtOhMcIptWuyRqDn(eTBdW){MeXawXgnKuj= '';for(dcDTOooitnc=(-692+692)/885; dcDTOooitnc < (33+909)/471; dcDTOooitnc++) {oy" ascii
    $s13 = "function YdtOhMcIptWuyRqDn(eTBdW){MeXawXgnKuj= '';for(dcDTOooitnc=(-692+692)/885; dcDTOooitnc < (33+909)/471; dcDTOooitnc++) {oy" ascii
    $s14 = " SObzF;}function ByTWJYPUCkiJRxA(YwwCzCJTyVwBMLiCY){eval(YwwCzCJTyVwBMLiCY)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}