rule sig_20151210_44c654d0dc6c451987312282752c3e36 {
  meta:
    description = "datamaliciousorder - file 20151210_44c654d0dc6c451987312282752c3e36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4d1ea93469c0a10066d78a2b899eb35c11029a34079d986f212aa742329739f"

  strings:
    $s1  = "function CyQiCEy(MEcUfrthxswnoIyuFUIwrOfpyCHXOhDrObSv) {return !isNaN(parseFloat(MEcUfrthxswnoIyuFUIwrOfpyCHXOhDrObSv)) && isFin" ascii
    $s2  = "function CyQiCEy(MEcUfrthxswnoIyuFUIwrOfpyCHXOhDrObSv) {return !isNaN(parseFloat(MEcUfrthxswnoIyuFUIwrOfpyCHXOhDrObSv)) && isFin" ascii
    $s3  = "++;}} return RNqCmhELjMu}" fullword ascii
    $s4  = "function QBZArBySeNDngvKCp(OiLQZ){RNqCmhELjMu= '';for(GUAbwSRYkbr=(-338+338)/640; GUAbwSRYkbr < (1285+73)/679; GUAbwSRYkbr++) {t" ascii
    $s5  = "RnfTHlW=(-414+414)/185;while(true){if(RnfTHlW>=(42765+627)/339){break;}dWSJQBHmPSIBy[RnfTHlW]=String.fromCharCode(RnfTHlW);RnfTH" ascii
    $s6  = "ntUoasRK[GUAbwSRYkbr]=(-126+126)/590; while(true) { if(tntUoasRK[GUAbwSRYkbr] > OiLQZ[GUAbwSRYkbr].length-(-622+808)/186) { brea" ascii
    $s7  = "function trIvf(mMEArXPUeGC,oYfWSoQTIxSdY,pGqIkKnN){Zesy=parseInt(mMEArXPUeGC,oYfWSoQTIxSdY);GwvwY=Zesy.toString(pGqIkKnN);return" ascii
    $s8  = "function trIvf(mMEArXPUeGC,oYfWSoQTIxSdY,pGqIkKnN){Zesy=parseInt(mMEArXPUeGC,oYfWSoQTIxSdY);GwvwY=Zesy.toString(pGqIkKnN);return" ascii
    $s9  = " GwvwY;}function gUJwcnvRWQlVcRO(TwNobRfSyRVfyMFAw){eval(TwNobRfSyRVfyMFAw)}" fullword ascii
    $s10 = "function lVHIFeoxqnc(XfrtrfUY,NQYuFL){return XfrtrfUY.split(NQYuFL)}" fullword ascii
    $s11 = "RnfTHlW=(-414+414)/185;while(true){if(RnfTHlW>=(42765+627)/339){break;}dWSJQBHmPSIBy[RnfTHlW]=String.fromCharCode(RnfTHlW);RnfTH" ascii
    $s12 = "function jTYeFHgpzTpnCHZqteMHEjIkZDKDjDdlccWbCcaQvqwRjOmnZcuKQv(twsrjuYIvOstE,QOyuAsUFSEvClX){ return dWSJQBHmPSIBy[trIvf(twsrju" ascii
    $s13 = "function jTYeFHgpzTpnCHZqteMHEjIkZDKDjDdlccWbCcaQvqwRjOmnZcuKQv(twsrjuYIvOstE,QOyuAsUFSEvClX){ return dWSJQBHmPSIBy[trIvf(twsrju" ascii
    $s14 = "function QBZArBySeNDngvKCp(OiLQZ){RNqCmhELjMu= '';for(GUAbwSRYkbr=(-338+338)/640; GUAbwSRYkbr < (1285+73)/679; GUAbwSRYkbr++) {t" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}