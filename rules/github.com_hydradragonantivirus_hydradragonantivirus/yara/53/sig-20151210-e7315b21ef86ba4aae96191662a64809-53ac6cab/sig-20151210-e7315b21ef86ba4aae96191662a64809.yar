rule sig_20151210_e7315b21ef86ba4aae96191662a64809 {
  meta:
    description = "datamaliciousorder - file 20151210_e7315b21ef86ba4aae96191662a64809.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e997bbc0a85e567a44bd91a05457a5b788af6c19c3f9a37c1239daa9f6b1021"

  strings:
    $s1  = "qcbtxkF=(-442+442)/680;while(true){if(qcbtxkF>=(97492+684)/767){break;}FMFWAGiUWQluC[qcbtxkF]=String.fromCharCode(qcbtxkF);qcbtx" ascii
    $s2  = " xOQCP;}function CYcfczfYmyCetHl(UPwYnfsLSOJdGKqBu){eval(UPwYnfsLSOJdGKqBu)}" fullword ascii
    $s3  = "function OiyzTVStkxbVHXWWoZOVTUvpYZsmCqlDEOcRGTTBHnsBNjMnMFIoyu(KUMGZlBhjcNdr,tzzGNvcluaTGAq){ return FMFWAGiUWQluC[DpujP(KUMGZl" ascii
    $s4  = "ibgLPL[UaCWzwfEayQ]=(-325+325)/505; while(true) { if(iYdibgLPL[UaCWzwfEayQ] > litAU[UaCWzwfEayQ].length-(-106+225)/119) { break;" ascii
    $s5  = "+;}} return fXDEnXIzvwx}" fullword ascii
    $s6  = "function DiyQhQcbHhgzhdBYt(litAU){fXDEnXIzvwx= '';for(UaCWzwfEayQ=(-50+50)/218; UaCWzwfEayQ < (-64+336)/136; UaCWzwfEayQ++) {iYd" ascii
    $s7  = "function OiyzTVStkxbVHXWWoZOVTUvpYZsmCqlDEOcRGTTBHnsBNjMnMFIoyu(KUMGZlBhjcNdr,tzzGNvcluaTGAq){ return FMFWAGiUWQluC[DpujP(KUMGZl" ascii
    $s8  = "function DpujP(EKVbKiyEybn,cyEIRdnQhhdaC,qyipzmGk){huIX=parseInt(EKVbKiyEybn,cyEIRdnQhhdaC);xOQCP=huIX.toString(qyipzmGk);return" ascii
    $s9  = "function DpujP(EKVbKiyEybn,cyEIRdnQhhdaC,qyipzmGk){huIX=parseInt(EKVbKiyEybn,cyEIRdnQhhdaC);xOQCP=huIX.toString(qyipzmGk);return" ascii
    $s10 = "qcbtxkF=(-442+442)/680;while(true){if(qcbtxkF>=(97492+684)/767){break;}FMFWAGiUWQluC[qcbtxkF]=String.fromCharCode(qcbtxkF);qcbtx" ascii
    $s11 = "function vNlRbFrcpXn(eNzLaWkv,eFUMJH){return eNzLaWkv.split(eFUMJH)}" fullword ascii
    $s12 = "function scAfPMs(lBckiEHuMNjEzhAxIfAtpjTzSMOtPfndHlIu) {return !isNaN(parseFloat(lBckiEHuMNjEzhAxIfAtpjTzSMOtPfndHlIu)) && isFin" ascii
    $s13 = "function scAfPMs(lBckiEHuMNjEzhAxIfAtpjTzSMOtPfndHlIu) {return !isNaN(parseFloat(lBckiEHuMNjEzhAxIfAtpjTzSMOtPfndHlIu)) && isFin" ascii
    $s14 = "function DiyQhQcbHhgzhdBYt(litAU){fXDEnXIzvwx= '';for(UaCWzwfEayQ=(-50+50)/218; UaCWzwfEayQ < (-64+336)/136; UaCWzwfEayQ++) {iYd" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}