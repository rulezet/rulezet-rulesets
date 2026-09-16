rule sig_20151210_aa83e56a59a5a38714ea4579b5be6a2e {
  meta:
    description = "datamaliciousorder - file 20151210_aa83e56a59a5a38714ea4579b5be6a2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e1b5745dba96faf6a54db6ed4c4dd29c6e2e0865c7ca0383e9c7704d72b5884"

  strings:
    $s1  = "function idRbASPzvsJELCfvwxNgmjiIIRJryLlpOpCzAnOJZUEgWYZWNRDvZP(TfLqhZKlUHEad,BdPwRrjtkMrVAQ){ return mENGtQKEzVjpu[NKMfM(TfLqhZ" ascii
    $s2  = "function idRbASPzvsJELCfvwxNgmjiIIRJryLlpOpCzAnOJZUEgWYZWNRDvZP(TfLqhZKlUHEad,BdPwRrjtkMrVAQ){ return mENGtQKEzVjpu[NKMfM(TfLqhZ" ascii
    $s3  = "function dfykJBi(WOZmWGXJsJQlAgoLPKjrdhJfaBrVnAoMLiUE) {return !isNaN(parseFloat(WOZmWGXJsJQlAgoLPKjrdhJfaBrVnAoMLiUE)) && isFin" ascii
    $s4  = "function dfykJBi(WOZmWGXJsJQlAgoLPKjrdhJfaBrVnAoMLiUE) {return !isNaN(parseFloat(WOZmWGXJsJQlAgoLPKjrdhJfaBrVnAoMLiUE)) && isFin" ascii
    $s5  = "function hXVygPSPHFb(puLdgJXH,zRBMjz){return puLdgJXH.split(zRBMjz)}" fullword ascii
    $s6  = "vkZreIL=(-95+95)/891;while(true){if(vkZreIL>=(8743+89)/69){break;}mENGtQKEzVjpu[vkZreIL]=String.fromCharCode(vkZreIL);vkZreIL++;" ascii
    $s7  = " WSjeH;}function dLSZKzymKzMwLei(iDdwaHaXQjaBCPJQu){eval(iDdwaHaXQjaBCPJQu)}" fullword ascii
    $s8  = "function NKMfM(kBOiTuNfwPD,pYslsBnvYXEap,DhlFicVp){jEXv=parseInt(kBOiTuNfwPD,pYslsBnvYXEap);WSjeH=jEXv.toString(DhlFicVp);return" ascii
    $s9  = "function MsGemKGCMWoRgjXHi(bfluA){GSKCeHNpHRu= '';for(ZIkxVuKXuOd=(-935+935)/576; ZIkxVuKXuOd < (68+748)/408; ZIkxVuKXuOd++) {Am" ascii
    $s10 = "++;}} return GSKCeHNpHRu}" fullword ascii
    $s11 = "function NKMfM(kBOiTuNfwPD,pYslsBnvYXEap,DhlFicVp){jEXv=parseInt(kBOiTuNfwPD,pYslsBnvYXEap);WSjeH=jEXv.toString(DhlFicVp);return" ascii
    $s12 = "function MsGemKGCMWoRgjXHi(bfluA){GSKCeHNpHRu= '';for(ZIkxVuKXuOd=(-935+935)/576; ZIkxVuKXuOd < (68+748)/408; ZIkxVuKXuOd++) {Am" ascii
    $s13 = "vkZreIL=(-95+95)/891;while(true){if(vkZreIL>=(8743+89)/69){break;}mENGtQKEzVjpu[vkZreIL]=String.fromCharCode(vkZreIL);vkZreIL++;" ascii
    $s14 = "UBRuhwp[ZIkxVuKXuOd]=(-756+756)/810; while(true) { if(AmUBRuhwp[ZIkxVuKXuOd] > bfluA[ZIkxVuKXuOd].length-(-472+792)/320) { break" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}