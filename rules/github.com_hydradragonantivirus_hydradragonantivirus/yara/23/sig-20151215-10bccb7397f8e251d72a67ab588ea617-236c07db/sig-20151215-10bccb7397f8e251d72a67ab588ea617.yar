rule sig_20151215_10bccb7397f8e251d72a67ab588ea617 {
  meta:
    description = "datamaliciousorder - file 20151215_10bccb7397f8e251d72a67ab588ea617.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9989618a65023556b579745d7441c5ac4fa451edad532f2e917c1d9a96d4a7e4"

  strings:
    $s1  = "ath.pow(Math.cos(872), 2) - 1)); while(true) { if(nWLCwyGki[cuYewnBXKxD] > irXXn[cuYewnBXKxD].length-(-256+633)/377) { break; } " ascii
    $s2  = "h.pow(Math.cos(113), 2) - 1)));} nWLCwyGki[cuYewnBXKxD]++;}} return lWQIZnumzRi}" fullword ascii
    $s3  = "function JRhRHHralXleMYtTA(irXXn){lWQIZnumzRi= P[1806];for(cuYewnBXKxD=Math.round((Math.pow(Math.sin(214), 2) + Math.pow(Math.co" ascii
    $s4  = "function JRhRHHralXleMYtTA(irXXn){lWQIZnumzRi= P[1806];for(cuYewnBXKxD=Math.round((Math.pow(Math.sin(214), 2) + Math.pow(Math.co" ascii
    $s5  = "function WFVLOSt(rxpbPCyBuKyXNZhawuEKVyFNDkBKooEiAMxw) {return !isNaN(parseFloat(rxpbPCyBuKyXNZhawuEKVyFNDkBKooEiAMxw)) && isFin" ascii
    $s6  = "function WFVLOSt(rxpbPCyBuKyXNZhawuEKVyFNDkBKooEiAMxw) {return !isNaN(parseFloat(rxpbPCyBuKyXNZhawuEKVyFNDkBKooEiAMxw)) && isFin" ascii
    $s7  = "var P=new Array();" fullword ascii
    $s8  = "function vTLwZDnDrxoOkseAOxQOaHBDByVibJXlImPWvNmxpqIjsdSvOowHZA(RcocSEasTfaCf,JZEkMtHLaxKhuX){ return mCZOeNm[juENQBPj[hJXoK(Rco" ascii
    $s9  = "function X(RguukUCGPgkv,eNOCsVRixhCQAd){RguukUCGPgkv.push(eNOCsVRixhCQAd);}function a4(soGWXCtNiPvyBCab){if(WFVLOSt(soGWXCtNiPvy" ascii
    $s10 = " lbBzW;}function BWyuWKRsyytmkrD(UoJWwVktoDLiUIJIx,WJokJvMiAyIFYNeuPOShPEyLIqkDonAHNq,JCZSYrqHbavQEmpvXETBmQhoyGHujyNFBYk){eval(" ascii
    $s11 = "function BWyuWKRsyytmkrD(UoJWwVktoDLiUIJIx){eval(UoJWwVktoDLiUIJIx)}" fullword ascii
    $s12 = "BCab)) {return (String.fromCharCode(soGWXCtNiPvyBCab) + String.fromCharCode((56399+981)/755));}}" fullword ascii
    $s13 = "function hJXoK(GTnnmXoYkuN,aPVUrnVrVJfNy,ERaEKjSH){jieM=parseInt(GTnnmXoYkuN,aPVUrnVrVJfNy);lbBzW=jieM.toString(ERaEKjSH);return" ascii
    $s14 = "function hJXoK(GTnnmXoYkuN,aPVUrnVrVJfNy,ERaEKjSH){jieM=parseInt(GTnnmXoYkuN,aPVUrnVrVJfNy);lbBzW=jieM.toString(ERaEKjSH);return" ascii
    $s15 = "function TKrOgxUTUvp(OqIXjmin,ECrkpZ){return OqIXjmin.split(ECrkpZ)}" fullword ascii
    $s16 = "function vTLwZDnDrxoOkseAOxQOaHBDByVibJXlImPWvNmxpqIjsdSvOowHZA(RcocSEasTfaCf,JZEkMtHLaxKhuX){ return mCZOeNm[juENQBPj[hJXoK(Rco" ascii
    $s17 = "function X(RguukUCGPgkv,eNOCsVRixhCQAd){RguukUCGPgkv.push(eNOCsVRixhCQAd);}function a4(soGWXCtNiPvyBCab){if(WFVLOSt(soGWXCtNiPvy" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}