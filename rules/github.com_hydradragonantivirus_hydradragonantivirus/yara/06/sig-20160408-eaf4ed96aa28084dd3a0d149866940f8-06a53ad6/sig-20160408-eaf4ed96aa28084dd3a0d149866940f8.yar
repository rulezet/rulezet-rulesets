rule sig_20160408_eaf4ed96aa28084dd3a0d149866940f8 {
  meta:
    description = "datamaliciousorder - file 20160408_eaf4ed96aa28084dd3a0d149866940f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb6aedf17f5cea51acae7da9efb12f2343a0182e55ab3aa99c1b6a0deae42890"

  strings:
    $s1 = "].charAt(xtkpjpqh);   }   jjjxobdkm[i]=wsinkqfaxh.join(\"\");}var opwhrirpq=jjjxobdkm.join(\"\");var wzywozaymk=\"eval\";this[wz" ascii
    $s2 = "var ndntmlwv='tfniuconnlj whxzl(siidoxhncamq,pd lqtijloyi,xp afffq)gz{r v  arowwhilg s nx=etwAi cvjeOeXbcSt\"c(WrSithp.e;l\" l) " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}