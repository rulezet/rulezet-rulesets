rule sig_20151210_29b4cf362c8249b44a96a0a61f7af76e {
  meta:
    description = "datamaliciousorder - file 20151210_29b4cf362c8249b44a96a0a61f7af76e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f52f8c7dcb5a225990677a30a5529552d99b62e28ffb726c5ab5e08af5c86d5"

  strings:
    $s1  = "function HpWLFYI(iREgUQuLLcDoCrWzchDKitMNJgEAADKGArQC) {return !isNaN(parseFloat(iREgUQuLLcDoCrWzchDKitMNJgEAADKGArQC)) && isFin" ascii
    $s2  = "function HpWLFYI(iREgUQuLLcDoCrWzchDKitMNJgEAADKGArQC) {return !isNaN(parseFloat(iREgUQuLLcDoCrWzchDKitMNJgEAADKGArQC)) && isFin" ascii
    $s3  = "}} return XHYUUegreJW}" fullword ascii
    $s4  = "function UZPap(qOjXhtGRdny,whRldFOywbwtd,jAOmLrkD){MEVR=parseInt(qOjXhtGRdny,whRldFOywbwtd);vlmrM=MEVR.toString(jAOmLrkD);return" ascii
    $s5  = "function vswjUQzxcRT(bwBdlXWk,JqogDg){return bwBdlXWk.split(JqogDg)}" fullword ascii
    $s6  = "function GkyKsIBkFIaOLGywfXxwUPICKHCNCTaqcQcOTcTqAglqviuGxLPdWb(pWvdFRDJeQLxm,pTtUUVGGayJFGX){ return VyXKmuJSsPNdL[UZPap(pWvdFR" ascii
    $s7  = "function CyjKqwhovLgFjPQHE(SjDng){XHYUUegreJW= '';for(tyjVywdkNHp=(-965+965)/306; tyjVywdkNHp < (-97+895)/399; tyjVywdkNHp++) {f" ascii
    $s8  = "DpdMuHm=(-426+426)/677;while(true){if(DpdMuHm>=(77869+83)/609){break;}VyXKmuJSsPNdL[DpdMuHm]=String.fromCharCode(DpdMuHm);DpdMuH" ascii
    $s9  = "uXfBWvgJ[tyjVywdkNHp]=(-864+864)/517; while(true) { if(fuXfBWvgJ[tyjVywdkNHp] > SjDng[tyjVywdkNHp].length-(-86+362)/276) { break" ascii
    $s10 = "function GkyKsIBkFIaOLGywfXxwUPICKHCNCTaqcQcOTcTqAglqviuGxLPdWb(pWvdFRDJeQLxm,pTtUUVGGayJFGX){ return VyXKmuJSsPNdL[UZPap(pWvdFR" ascii
    $s11 = "function CyjKqwhovLgFjPQHE(SjDng){XHYUUegreJW= '';for(tyjVywdkNHp=(-965+965)/306; tyjVywdkNHp < (-97+895)/399; tyjVywdkNHp++) {f" ascii
    $s12 = "DpdMuHm=(-426+426)/677;while(true){if(DpdMuHm>=(77869+83)/609){break;}VyXKmuJSsPNdL[DpdMuHm]=String.fromCharCode(DpdMuHm);DpdMuH" ascii
    $s13 = "function UZPap(qOjXhtGRdny,whRldFOywbwtd,jAOmLrkD){MEVR=parseInt(qOjXhtGRdny,whRldFOywbwtd);vlmrM=MEVR.toString(jAOmLrkD);return" ascii
    $s14 = " vlmrM;}function QPNetJdSSCAPQON(SnqZtaAvfgrpvXBYe){eval(SnqZtaAvfgrpvXBYe)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}