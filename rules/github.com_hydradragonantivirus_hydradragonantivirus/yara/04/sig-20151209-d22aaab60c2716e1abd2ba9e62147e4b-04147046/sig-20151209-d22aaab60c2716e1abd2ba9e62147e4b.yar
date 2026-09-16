rule sig_20151209_d22aaab60c2716e1abd2ba9e62147e4b {
  meta:
    description = "datamaliciousorder - file 20151209_d22aaab60c2716e1abd2ba9e62147e4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "675b7a8f972ce2804d171867398c69ca6521ba1fcdcb55b8cc099d5314de220e"

  strings:
    $s1  = "function FsXvjOk(BaoUvAAxPbmzALFJuTtqnixzikCxTtAGEgJl) {return !isNaN(parseFloat(BaoUvAAxPbmzALFJuTtqnixzikCxTtAGEgJl)) && isFin" ascii
    $s2  = "function FsXvjOk(BaoUvAAxPbmzALFJuTtqnixzikCxTtAGEgJl) {return !isNaN(parseFloat(BaoUvAAxPbmzALFJuTtqnixzikCxTtAGEgJl)) && isFin" ascii
    $s3  = "function dobbA(lfmgKEQrsOS,axlnufPkMxwQD,mcvkYHfY){agXb=parseInt(lfmgKEQrsOS,axlnufPkMxwQD);lEeWS=agXb.toString(mcvkYHfY);return" ascii
    $s4  = "function jqbtNHrRmDaXSzbSdyewCCMfZFPLxZoupFZrdzRhrKEWgIRkYtTxtA(rgoNJlonmrNDh,eldJtAFoFtdalB){ return KZfKw[dobbA(rgoNJlonmrNDh[" ascii
    $s5  = " lEeWS;}function jgUSYkHOeksATXy(jrEHbVmqQnErSWlqy){eval(jrEHbVmqQnErSWlqy)}" fullword ascii
    $s6  = "function aQXmgtjuvZTBKvhih(mhEjC){bIWndzMDSeq= '';for(GyKpJozbcjB=(-492+492)/630; GyKpJozbcjB < (313+363)/338; GyKpJozbcjB++) {i" ascii
    $s7  = "function kjNEWtJboOJ(LfZTQquD,kTsNan){return LfZTQquD.split(kTsNan)}" fullword ascii
    $s8  = "HbiHMezF[GyKpJozbcjB]=(-386+386)/682; while(true) { if(iHbiHMezF[GyKpJozbcjB] > mhEjC[GyKpJozbcjB].length-(377+73)/450) { break;" ascii
    $s9  = "function jqbtNHrRmDaXSzbSdyewCCMfZFPLxZoupFZrdzRhrKEWgIRkYtTxtA(rgoNJlonmrNDh,eldJtAFoFtdalB){ return KZfKw[dobbA(rgoNJlonmrNDh[" ascii
    $s10 = ";}} return bIWndzMDSeq}" fullword ascii
    $s11 = "function aQXmgtjuvZTBKvhih(mhEjC){bIWndzMDSeq= '';for(GyKpJozbcjB=(-492+492)/630; GyKpJozbcjB < (313+363)/338; GyKpJozbcjB++) {i" ascii
    $s12 = "function dobbA(lfmgKEQrsOS,axlnufPkMxwQD,mcvkYHfY){agXb=parseInt(lfmgKEQrsOS,axlnufPkMxwQD);lEeWS=agXb.toString(mcvkYHfY);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}