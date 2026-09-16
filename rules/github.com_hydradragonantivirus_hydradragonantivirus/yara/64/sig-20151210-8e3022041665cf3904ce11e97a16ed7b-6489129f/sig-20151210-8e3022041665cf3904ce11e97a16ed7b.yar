rule sig_20151210_8e3022041665cf3904ce11e97a16ed7b {
  meta:
    description = "datamaliciousorder - file 20151210_8e3022041665cf3904ce11e97a16ed7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0734d99b39b205243f56c432aa319552e543a56a7a4c43d750e1d57c708746c6"

  strings:
    $s1  = "function aFPeeAeewtP(QmxcMDFG,TQqZhu){return QmxcMDFG.split(TQqZhu)}" fullword ascii
    $s2  = " MEXAz;}function BpUTMPJVgycJxKL(woxTeEpREzSwJQbMf){eval(woxTeEpREzSwJQbMf)}" fullword ascii
    $s3  = "function dTqnR(PLFQPYkccfx,EdmIigHrjbWOj,nYTBzwzh){xooz=parseInt(PLFQPYkccfx,EdmIigHrjbWOj);MEXAz=xooz.toString(nYTBzwzh);return" ascii
    $s4  = "function KbEGYtz(NOwzktfrgsiMFZhYjRoFhrlZGugWWPFysjhg) {return !isNaN(parseFloat(NOwzktfrgsiMFZhYjRoFhrlZGugWWPFysjhg)) && isFin" ascii
    $s5  = "function KbEGYtz(NOwzktfrgsiMFZhYjRoFhrlZGugWWPFysjhg) {return !isNaN(parseFloat(NOwzktfrgsiMFZhYjRoFhrlZGugWWPFysjhg)) && isFin" ascii
    $s6  = "ODFlzt[qFRdqYttltk]=(-8+8)/745; while(true) { if(GmjODFlzt[qFRdqYttltk] > awFfh[qFRdqYttltk].length-(-64+320)/256) { break; } if" ascii
    $s7  = "function YddRGZehchALDucDG(awFfh){wmYaeJIpVhH= '';for(qFRdqYttltk=(-624+624)/13; qFRdqYttltk < (-19+103)/42; qFRdqYttltk++) {Gmj" ascii
    $s8  = "function dTqnR(PLFQPYkccfx,EdmIigHrjbWOj,nYTBzwzh){xooz=parseInt(PLFQPYkccfx,EdmIigHrjbWOj);MEXAz=xooz.toString(nYTBzwzh);return" ascii
    $s9  = "function YddRGZehchALDucDG(awFfh){wmYaeJIpVhH= '';for(qFRdqYttltk=(-624+624)/13; qFRdqYttltk < (-19+103)/42; qFRdqYttltk++) {Gmj" ascii
    $s10 = "function QOaSGxJKWLZFtKrFrWYBIlNcJfjYSptmXbtPKvSwpFmKZcaOcHEcRk(zxtiXmqABcpTA,CajmjmAuMgSoRh){ return cHXrw[dTqnR(zxtiXmqABcpTA[" ascii
    $s11 = "function QOaSGxJKWLZFtKrFrWYBIlNcJfjYSptmXbtPKvSwpFmKZcaOcHEcRk(zxtiXmqABcpTA,CajmjmAuMgSoRh){ return cHXrw[dTqnR(zxtiXmqABcpTA[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}