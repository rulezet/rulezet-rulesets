rule sig_20151209_de9dd0381bbe1091025b9fc52b186dd2 {
  meta:
    description = "datamaliciousorder - file 20151209_de9dd0381bbe1091025b9fc52b186dd2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9efa353ce11e5e9aafeda9d96322434c13caeea28c71a17d9fbce63d9bc3042f"

  strings:
    $s1  = "function SPefRuNOlARaceemM(gDMmg){ckEFMxERhVs= '';for(IwFaaJIwgxx=(-79+79)/369; IwFaaJIwgxx < (1315+347)/831; IwFaaJIwgxx++) {AH" ascii
    $s2  = "function wozONjy(tFamQLevYaQKlDwXjGPTJearRjsdFQUNEADE) {return !isNaN(parseFloat(tFamQLevYaQKlDwXjGPTJearRjsdFQUNEADE)) && isFin" ascii
    $s3  = "function wozONjy(tFamQLevYaQKlDwXjGPTJearRjsdFQUNEADE) {return !isNaN(parseFloat(tFamQLevYaQKlDwXjGPTJearRjsdFQUNEADE)) && isFin" ascii
    $s4  = "function SPefRuNOlARaceemM(gDMmg){ckEFMxERhVs= '';for(IwFaaJIwgxx=(-79+79)/369; IwFaaJIwgxx < (1315+347)/831; IwFaaJIwgxx++) {AH" ascii
    $s5  = "function YFfTN(ETuYHutDDls,ehRKyQpvOwxoj,JlPdCzbR){TXuN=parseInt(ETuYHutDDls,ehRKyQpvOwxoj);Lwsml=TXuN.toString(JlPdCzbR);return" ascii
    $s6  = "function OwrUwemBSRq(mAkmVrwN,gtfgQD){return mAkmVrwN.split(gtfgQD)}" fullword ascii
    $s7  = "eSMaCdl[IwFaaJIwgxx]=(-650+650)/169; while(true) { if(AHeSMaCdl[IwFaaJIwgxx] > gDMmg[IwFaaJIwgxx].length-(-488+927)/439) { break" ascii
    $s8  = "+;}} return ckEFMxERhVs}" fullword ascii
    $s9  = "function YFfTN(ETuYHutDDls,ehRKyQpvOwxoj,JlPdCzbR){TXuN=parseInt(ETuYHutDDls,ehRKyQpvOwxoj);Lwsml=TXuN.toString(JlPdCzbR);return" ascii
    $s10 = "function WTmxpZbOlPVEepZsmgYMKAFGuZJRVadjRFkNvOLDdiwpSnUgCcXsAZ(beAqBYJsDFMTv,smJyeELEgVzQbR){ return tzsxK[YFfTN(beAqBYJsDFMTv[" ascii
    $s11 = "function WTmxpZbOlPVEepZsmgYMKAFGuZJRVadjRFkNvOLDdiwpSnUgCcXsAZ(beAqBYJsDFMTv,smJyeELEgVzQbR){ return tzsxK[YFfTN(beAqBYJsDFMTv[" ascii
    $s12 = " Lwsml;}function srgXqsdBZRFzYCh(GeMUkoOCpIcWOtrkD){eval(GeMUkoOCpIcWOtrkD)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}