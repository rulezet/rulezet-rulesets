rule sig_20151209_22dccb7a6d14b857be2e340dd13a991e {
  meta:
    description = "datamaliciousorder - file 20151209_22dccb7a6d14b857be2e340dd13a991e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc42bf60918600ce8efed1cdc0411be99bbf5b031af32fcba06980e0820e9c7e"

  strings:
    $s1  = "function jpeGn(GgNiWtoUsTg,ZDyfTLXQekyeo,rjqcTxuf){QvMb=parseInt(GgNiWtoUsTg,ZDyfTLXQekyeo);zmPns=QvMb.toString(rjqcTxuf);return" ascii
    $s2  = "function eysDrHKHdTaCJftDhPxLuwKlUDBxXiEcciGCepyqSSFFhkqwQkkMYd(DQOnTPUcBXsDs,QIJtXFxAUCqLDi){ return NHMIX[jpeGn(DQOnTPUcBXsDs[" ascii
    $s3  = "function eysDrHKHdTaCJftDhPxLuwKlUDBxXiEcciGCepyqSSFFhkqwQkkMYd(DQOnTPUcBXsDs,QIJtXFxAUCqLDi){ return NHMIX[jpeGn(DQOnTPUcBXsDs[" ascii
    $s4  = "function RbKRdqXTbSvMyQVZY(mkcsn){dmaSjAuKSen= '';for(qGmfhYBijdc=(-569+569)/518; qGmfhYBijdc < (1699+129)/914; qGmfhYBijdc++) {" ascii
    $s5  = "]++;}} return dmaSjAuKSen}" fullword ascii
    $s6  = "function RbKRdqXTbSvMyQVZY(mkcsn){dmaSjAuKSen= '';for(qGmfhYBijdc=(-569+569)/518; qGmfhYBijdc < (1699+129)/914; qGmfhYBijdc++) {" ascii
    $s7  = "function wkcIvhCjgsD(DkGWjNjZ,wdqHpg){return DkGWjNjZ.split(wdqHpg)}" fullword ascii
    $s8  = " zmPns;}function bywYnmIEOnlvkCl(DMUzAsaHCTuOaawPn){eval(DMUzAsaHCTuOaawPn)}" fullword ascii
    $s9  = "function jpeGn(GgNiWtoUsTg,ZDyfTLXQekyeo,rjqcTxuf){QvMb=parseInt(GgNiWtoUsTg,ZDyfTLXQekyeo);zmPns=QvMb.toString(rjqcTxuf);return" ascii
    $s10 = "UYsygQvHo[qGmfhYBijdc]=(-279+279)/954; while(true) { if(UYsygQvHo[qGmfhYBijdc] > mkcsn[qGmfhYBijdc].length-(-123+753)/630) { bre" ascii
    $s11 = "function FPzvuky(CfmwdOKXBAaduawURFPuKCxRcAQQMqiGykGr) {return !isNaN(parseFloat(CfmwdOKXBAaduawURFPuKCxRcAQQMqiGykGr)) && isFin" ascii
    $s12 = "function FPzvuky(CfmwdOKXBAaduawURFPuKCxRcAQQMqiGykGr) {return !isNaN(parseFloat(CfmwdOKXBAaduawURFPuKCxRcAQQMqiGykGr)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}