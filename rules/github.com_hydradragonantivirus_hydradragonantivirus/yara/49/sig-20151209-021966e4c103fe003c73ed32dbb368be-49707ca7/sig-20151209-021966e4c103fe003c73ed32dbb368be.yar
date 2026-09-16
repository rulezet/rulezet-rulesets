rule sig_20151209_021966e4c103fe003c73ed32dbb368be {
  meta:
    description = "datamaliciousorder - file 20151209_021966e4c103fe003c73ed32dbb368be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de7aa138dfbca7975d1c9b030adbb7bfcf1cafe97d5748ef59e437ea42e00934"

  strings:
    $s1  = "function HheLmSl(HUQcIuXzuLNJpIIcWNbcSLKlEnzjlkVYDXXC) {return !isNaN(parseFloat(HUQcIuXzuLNJpIIcWNbcSLKlEnzjlkVYDXXC)) && isFin" ascii
    $s2  = "function HheLmSl(HUQcIuXzuLNJpIIcWNbcSLKlEnzjlkVYDXXC) {return !isNaN(parseFloat(HUQcIuXzuLNJpIIcWNbcSLKlEnzjlkVYDXXC)) && isFin" ascii
    $s3  = "function oyBgC(YYUkypaxYhj,NMmdSdQFAwAVq,evPeTPBp){fFqb=parseInt(YYUkypaxYhj,NMmdSdQFAwAVq);zZvlu=fFqb.toString(evPeTPBp);return" ascii
    $s4  = "function qmKPbmTEVNwaoldMRBUSNLazOzNAnMcJFZjzcPcRYTUxuvhLKdyEKs(ObysmzAGkYOzg,SBmYhoJkKPpreB){ return yAEYv[oyBgC(ObysmzAGkYOzg[" ascii
    $s5  = "function eCnOgxktBHgRqziWt(BnSOR){eMMMouZzSGG= '';for(jqJAECMQhIX=(-927+927)/219; jqJAECMQhIX < (1075+191)/633; jqJAECMQhIX++) {" ascii
    $s6  = " zZvlu;}function UBVzuTkdcUnAKGO(xSdrSMOhvwoqREcUP){eval(xSdrSMOhvwoqREcUP)}" fullword ascii
    $s7  = "function fFzMNngyjvf(pbUCvJtD,PvsgQC){return pbUCvJtD.split(PvsgQC)}" fullword ascii
    $s8  = "function qmKPbmTEVNwaoldMRBUSNLazOzNAnMcJFZjzcPcRYTUxuvhLKdyEKs(ObysmzAGkYOzg,SBmYhoJkKPpreB){ return yAEYv[oyBgC(ObysmzAGkYOzg[" ascii
    $s9  = "joyJjcLYZ[jqJAECMQhIX]=(-246+246)/259; while(true) { if(joyJjcLYZ[jqJAECMQhIX] > BnSOR[jqJAECMQhIX].length-(734+221)/955) { brea" ascii
    $s10 = "+;}} return eMMMouZzSGG}" fullword ascii
    $s11 = "function eCnOgxktBHgRqziWt(BnSOR){eMMMouZzSGG= '';for(jqJAECMQhIX=(-927+927)/219; jqJAECMQhIX < (1075+191)/633; jqJAECMQhIX++) {" ascii
    $s12 = "function oyBgC(YYUkypaxYhj,NMmdSdQFAwAVq,evPeTPBp){fFqb=parseInt(YYUkypaxYhj,NMmdSdQFAwAVq);zZvlu=fFqb.toString(evPeTPBp);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}