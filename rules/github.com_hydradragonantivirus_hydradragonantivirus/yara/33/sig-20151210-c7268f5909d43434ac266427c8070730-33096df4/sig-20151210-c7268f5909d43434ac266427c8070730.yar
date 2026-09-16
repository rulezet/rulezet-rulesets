rule sig_20151210_c7268f5909d43434ac266427c8070730 {
  meta:
    description = "datamaliciousorder - file 20151210_c7268f5909d43434ac266427c8070730.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24e7802614e56ab8f339087e75c957dd7793aeb7e48b100d245b5c964061e921"

  strings:
    $s1  = "function fVITufW(QZlgzaNwdOvNkgFQykScixYWeIWLKcwHFJKQ) {return !isNaN(parseFloat(QZlgzaNwdOvNkgFQykScixYWeIWLKcwHFJKQ)) && isFin" ascii
    $s2  = "function fVITufW(QZlgzaNwdOvNkgFQykScixYWeIWLKcwHFJKQ) {return !isNaN(parseFloat(QZlgzaNwdOvNkgFQykScixYWeIWLKcwHFJKQ)) && isFin" ascii
    $s3  = "function TpyoynctOED(xLvYSbdh,ZRYGiV){return xLvYSbdh.split(ZRYGiV)}" fullword ascii
    $s4  = "XUnyWIq=(-697+697)/857;while(true){if(XUnyWIq>=(112172+340)/879){break;}RzZYkBZbyjpGu[XUnyWIq]=String.fromCharCode(XUnyWIq);XUny" ascii
    $s5  = "function ORgqaKUrkvlStkMfCuGMbYdYeWoKBFEKuxkbRjqpbDuEtEPbZPiTuP(MFRPzGxpMxxka,AsIKebnBTTFltP){ return RzZYkBZbyjpGu[XaSzz(MFRPzG" ascii
    $s6  = "function jcBNATKeuaxWHnMvU(FwnSS){CYgbmTXmrkp= '';for(rMWuuNZHDux=(-130+130)/159; rMWuuNZHDux < (1611+233)/922; rMWuuNZHDux++) {" ascii
    $s7  = "yTgDkWUaQ[rMWuuNZHDux]=(-50+50)/278; while(true) { if(yTgDkWUaQ[rMWuuNZHDux] > FwnSS[rMWuuNZHDux].length-(560+104)/664) { break;" ascii
    $s8  = "function ORgqaKUrkvlStkMfCuGMbYdYeWoKBFEKuxkbRjqpbDuEtEPbZPiTuP(MFRPzGxpMxxka,AsIKebnBTTFltP){ return RzZYkBZbyjpGu[XaSzz(MFRPzG" ascii
    $s9  = "XUnyWIq=(-697+697)/857;while(true){if(XUnyWIq>=(112172+340)/879){break;}RzZYkBZbyjpGu[XUnyWIq]=String.fromCharCode(XUnyWIq);XUny" ascii
    $s10 = "function jcBNATKeuaxWHnMvU(FwnSS){CYgbmTXmrkp= '';for(rMWuuNZHDux=(-130+130)/159; rMWuuNZHDux < (1611+233)/922; rMWuuNZHDux++) {" ascii
    $s11 = " xvYBU;}function JKNnPFvlpmphoTc(zoTuKFXJlLZUkSFYr){eval(zoTuKFXJlLZUkSFYr)}" fullword ascii
    $s12 = ";}} return CYgbmTXmrkp}" fullword ascii
    $s13 = "function XaSzz(nEZLRUHcAbi,SSAjrQeuSkyfM,DNAXigVA){SSBR=parseInt(nEZLRUHcAbi,SSAjrQeuSkyfM);xvYBU=SSBR.toString(DNAXigVA);return" ascii
    $s14 = "function XaSzz(nEZLRUHcAbi,SSAjrQeuSkyfM,DNAXigVA){SSBR=parseInt(nEZLRUHcAbi,SSAjrQeuSkyfM);xvYBU=SSBR.toString(DNAXigVA);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}