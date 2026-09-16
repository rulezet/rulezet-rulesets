rule sig_20151210_f8f759925811caeb709e81652584a7af {
  meta:
    description = "datamaliciousorder - file 20151210_f8f759925811caeb709e81652584a7af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da8d949801924a97ebd09be4152fa7c1ae9004cb4b58ffa6183ef095645dcd4e"

  strings:
    $s1  = "function rqWjWfP(siYKkrSuItVZLvNJHxcmZPGiaTUWZVvJmRaD) {return !isNaN(parseFloat(siYKkrSuItVZLvNJHxcmZPGiaTUWZVvJmRaD)) && isFin" ascii
    $s2  = "function rqWjWfP(siYKkrSuItVZLvNJHxcmZPGiaTUWZVvJmRaD) {return !isNaN(parseFloat(siYKkrSuItVZLvNJHxcmZPGiaTUWZVvJmRaD)) && isFin" ascii
    $s3  = "dvZNrTl[FPrmerwmOLq]=(-588+588)/522; while(true) { if(KSdvZNrTl[FPrmerwmOLq] > fgnxt[FPrmerwmOLq].length-(191+378)/569) { break;" ascii
    $s4  = "function NkgTJ(cngwuKoxCoG,fdntIPeWeqiwP,glfnZSfa){QAcu=parseInt(cngwuKoxCoG,fdntIPeWeqiwP);Ngzpu=QAcu.toString(glfnZSfa);return" ascii
    $s5  = "+;}} return uszIaBqUlMq}" fullword ascii
    $s6  = "mMCFTsW=(-931+931)/825;while(true){if(mMCFTsW>=(110419+173)/864){break;}qrYIjHCTkntQi[mMCFTsW]=String.fromCharCode(mMCFTsW);mMCF" ascii
    $s7  = "function fYRADYcdWbGmiQHnA(fgnxt){uszIaBqUlMq= '';for(FPrmerwmOLq=(-246+246)/89; FPrmerwmOLq < (293+339)/316; FPrmerwmOLq++) {KS" ascii
    $s8  = "function ZqZJBcKTNbXIDyZSjuldwwzcUjhwSHeCQEsGcmTecyqGuaqlmRdIJd(GCQBdRfRNkTEF,dtqAlEniEGXhST){ return qrYIjHCTkntQi[NkgTJ(GCQBdR" ascii
    $s9  = "function NkgTJ(cngwuKoxCoG,fdntIPeWeqiwP,glfnZSfa){QAcu=parseInt(cngwuKoxCoG,fdntIPeWeqiwP);Ngzpu=QAcu.toString(glfnZSfa);return" ascii
    $s10 = " Ngzpu;}function CqkaoEcjEPrLTBn(SQUWYfSGguTQtZumf){eval(SQUWYfSGguTQtZumf)}" fullword ascii
    $s11 = "function fYRADYcdWbGmiQHnA(fgnxt){uszIaBqUlMq= '';for(FPrmerwmOLq=(-246+246)/89; FPrmerwmOLq < (293+339)/316; FPrmerwmOLq++) {KS" ascii
    $s12 = "mMCFTsW=(-931+931)/825;while(true){if(mMCFTsW>=(110419+173)/864){break;}qrYIjHCTkntQi[mMCFTsW]=String.fromCharCode(mMCFTsW);mMCF" ascii
    $s13 = "function lYAbKZHowsr(mhQYrZLk,mLJviL){return mhQYrZLk.split(mLJviL)}" fullword ascii
    $s14 = "function ZqZJBcKTNbXIDyZSjuldwwzcUjhwSHeCQEsGcmTecyqGuaqlmRdIJd(GCQBdRfRNkTEF,dtqAlEniEGXhST){ return qrYIjHCTkntQi[NkgTJ(GCQBdR" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}