rule sig_20151217_987aab488627c0756235dcd40094db15 {
  meta:
    description = "datamaliciousorder - file 20151217_987aab488627c0756235dcd40094db15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0cae415852393fb450016c0e7a6427ec47c269152880473b63ee1f04b304916"

  strings:
    $s1  = "ath.cos(99), 2) - 1)));} FVZeFaORn[ZtyseKImEoV]++;}ZtyseKImEoV++;} return IcOSkfgEWKl}" fullword ascii
    $s2  = ") - 1));while(true){if (ZtyseKImEoV >= (4912+590)/917){break;}FVZeFaORn[ZtyseKImEoV]=Math.round((Math.pow(Math.sin(32), 2) + Mat" ascii
    $s3  = "function STNLNNFHxfLauWlBr(VfNSC){IcOSkfgEWKl= '';ZtyseKImEoV=Math.round((Math.pow(Math.sin(429), 2) + Math.pow(Math.cos(429), 2" ascii
    $s4  = "h.pow(Math.cos(32), 2) - 1)); while(true) { if(FVZeFaORn[ZtyseKImEoV] > VfNSC[ZtyseKImEoV].length-(529+131)/660) { break; } if (" ascii
    $s5  = "function STNLNNFHxfLauWlBr(VfNSC){IcOSkfgEWKl= '';ZtyseKImEoV=Math.round((Math.pow(Math.sin(429), 2) + Math.pow(Math.cos(429), 2" ascii
    $s6  = "function mPiMOSZ(pasmVUNlqLONUEpSeAPZJmeWsQUzHnFDJLNH) {return !CHffWRtmvjX(YfnjyhdxJznlwXd(pasmVUNlqLONUEpSeAPZJmeWsQUzHnFDJLNH" ascii
    $s7  = "var j = new Array();j[0]=[];j[0][0]='d';j[0][1]='a';j[0][2]='d';j[0][3]='a';j[0][4]='46';j[0][5]='3d';j[0][6]='42';j[0][7]='14';" ascii
    $s8  = "function MOnYrVoLJzmPTzOGN(ZmsQdzKXKj,aMkuPPDShw) {return parseInt(ZmsQdzKXKj,aMkuPPDShw);}" fullword ascii
    $s9  = "function RWsZwwHddSLUVfg(elxBgZcfapmlpCfyR,XExNBUiKKkIpSYEJZsSYuDfhqUWJnhubke,lzcetiqCiJJBLfxVhXPffgujMWizuITeiUb){eval(elxBgZcf" ascii
    $s10 = "function RWsZwwHddSLUVfg(elxBgZcfapmlpCfyR,XExNBUiKKkIpSYEJZsSYuDfhqUWJnhubke,lzcetiqCiJJBLfxVhXPffgujMWizuITeiUb){eval(elxBgZcf" ascii
    $s11 = "function YfnjyhdxJznlwXd(jDVPdCBPfTvQRkbfPPB) {return parseFloat(jDVPdCBPfTvQRkbfPPB);}" fullword ascii
    $s12 = "function Y(bQOebpftHeOk,oglfjQeWitXOqj){bQOebpftHeOk.push(oglfjQeWitXOqj);}" fullword ascii
    $s13 = "function xytHOZzedxEeNoTpjIiUJMBUdqrQqPzPqZiLsYREFnlUPnfYpNLOVY(LQqYNLZHHqbCR,bbJXHcqHsmijon){ return ycmVolC[QKAAvDeN[ZpALY(LQq" ascii
    $s14 = "function mPiMOSZ(pasmVUNlqLONUEpSeAPZJmeWsQUzHnFDJLNH) {return !CHffWRtmvjX(YfnjyhdxJznlwXd(pasmVUNlqLONUEpSeAPZJmeWsQUzHnFDJLNH" ascii
    $s15 = "function x(ceMJdghnaccvSy,dWrNioaETfpJi,XgUpNPdcMZC) {ceMJdghnaccvSy[dWrNioaETfpJi]=XgUpNPdcMZC;}" fullword ascii
    $s16 = "function xytHOZzedxEeNoTpjIiUJMBUdqrQqPzPqZiLsYREFnlUPnfYpNLOVY(LQqYNLZHHqbCR,bbJXHcqHsmijon){ return ycmVolC[QKAAvDeN[ZpALY(LQq" ascii
    $s17 = "function ccfeIGfZLBqc(ebOISxkwtXWDz) {return isFinite(ebOISxkwtXWDz);}" fullword ascii
    $s18 = "function CHffWRtmvjX(dNpeUeItMYPFSw) {return isNaN(dNpeUeItMYPFSw);}" fullword ascii
    $s19 = "K);return vbKHg;}" fullword ascii
    $s20 = "function ZpALY(eWexXRWjOvS,IjLjfLMDpwIRB,cRLtZzMK){gQYl=MOnYrVoLJzmPTzOGN(eWexXRWjOvS,IjLjfLMDpwIRB);vbKHg=gQYl.toString(cRLtZzM" ascii

  condition:
    uint16(0) == 0x4b51 and
    8 of them
}