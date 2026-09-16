rule sig_20151211_2dfb91849e209fca79d4013263ae1bd3 {
  meta:
    description = "datamaliciousorder - file 20151211_2dfb91849e209fca79d4013263ae1bd3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c55783d57a01dbb55980b080c3a456ddf765c5483032fcf101b096de069c816"

  strings:
    $s1  = "function yxxNPQA(niGjNKqnzswitqUngLeoXlakGFgbAeQHXBeI) {return !isNaN(parseFloat(niGjNKqnzswitqUngLeoXlakGFgbAeQHXBeI)) && isFin" ascii
    $s2  = "function yxxNPQA(niGjNKqnzswitqUngLeoXlakGFgbAeQHXBeI) {return !isNaN(parseFloat(niGjNKqnzswitqUngLeoXlakGFgbAeQHXBeI)) && isFin" ascii
    $s3  = "var K=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4e\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = "var G=new Array(\"2a\",\"2a\",\"29\",\"2c\",\"2d\",\"28\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s5  = "function gbACoXgvDpTIwAVMtCNUTMqszzrXSdsmQhLLYjKPOXBVSQNrkfuYei(dQQZLfnmCkYPm,ygoLiWrQderqjQ){ return aQgBt[OYRRZ(dQQZLfnmCkYPm[" ascii
    $s6  = "function OYRRZ(QzjdYKHVoSB,BrxfHxgopjjXf,vSfAKbQy){nHmj=parseInt(QzjdYKHVoSB,BrxfHxgopjjXf);FwUOi=nHmj.toString(vSfAKbQy);return" ascii
    $s7  = "function gbACoXgvDpTIwAVMtCNUTMqszzrXSdsmQhLLYjKPOXBVSQNrkfuYei(dQQZLfnmCkYPm,ygoLiWrQderqjQ){ return aQgBt[OYRRZ(dQQZLfnmCkYPm[" ascii
    $s8  = "function OYRRZ(QzjdYKHVoSB,BrxfHxgopjjXf,vSfAKbQy){nHmj=parseInt(QzjdYKHVoSB,BrxfHxgopjjXf);FwUOi=nHmj.toString(vSfAKbQy);return" ascii
    $s9  = " FwUOi;}function bvzXwwadGsCoqCp(kMczhFnVdsLUTGvOa){eval(kMczhFnVdsLUTGvOa)}" fullword ascii
    $s10 = "function mqdjkIayzAcCQYdJp(fGdXl){CIqUhXgsmny= '';JbrGNGRyHEv=(-392+392)/188; while(true){if(JbrGNGRyHEv >= (361+475)/418)break;" ascii
    $s11 = "IiuImXgeg[JbrGNGRyHEv]=(-558+558)/283; while(true) { if(IiuImXgeg[JbrGNGRyHEv] > fGdXl[JbrGNGRyHEv].length-(-379+933)/554) { bre" ascii
    $s12 = "function gPMGoapueRy(CGKdcgaK,PNapAe){return CGKdcgaK.split(PNapAe)}" fullword ascii
    $s13 = "v]++;}JbrGNGRyHEv++;} return CIqUhXgsmny}" fullword ascii
    $s14 = "var G=new Array(\"2a\",\"2a\",\"29\",\"2c\",\"2d\",\"28\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s15 = "function mqdjkIayzAcCQYdJp(fGdXl){CIqUhXgsmny= '';JbrGNGRyHEv=(-392+392)/188; while(true){if(JbrGNGRyHEv >= (361+475)/418)break;" ascii
    $s16 = "var K=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4e\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}