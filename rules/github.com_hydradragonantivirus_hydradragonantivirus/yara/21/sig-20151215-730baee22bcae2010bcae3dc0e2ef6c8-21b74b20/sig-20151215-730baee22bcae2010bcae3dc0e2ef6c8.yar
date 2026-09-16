rule sig_20151215_730baee22bcae2010bcae3dc0e2ef6c8 {
  meta:
    description = "datamaliciousorder - file 20151215_730baee22bcae2010bcae3dc0e2ef6c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ad2059806f561c1a2d0856c2ef1f48679174c7f780be120e71862079bafae66"

  strings:
    $s1  = "Math.pow(Math.cos(724), 2) - 1)); while(true) { if(vGzKBNNhm[FmOpxxCdIWm] > mjsjP[FmOpxxCdIWm].length-(263+61)/324) { break; } i" ascii
    $s2  = "ow(Math.cos(300), 2) - 1)));} vGzKBNNhm[FmOpxxCdIWm]++;}} return VuqjwPfvVsN}" fullword ascii
    $s3  = "function SGdYKUGVPXOEQvtYJ(mjsjP){VuqjwPfvVsN= h[1795];for(FmOpxxCdIWm=Math.round((Math.pow(Math.sin(721), 2) + Math.pow(Math.co" ascii
    $s4  = "function SGdYKUGVPXOEQvtYJ(mjsjP){VuqjwPfvVsN= h[1795];for(FmOpxxCdIWm=Math.round((Math.pow(Math.sin(721), 2) + Math.pow(Math.co" ascii
    $s5  = "function G(WFqVYkiMrnWR,OSYpLlpvuBzDCM){WFqVYkiMrnWR.push(OSYpLlpvuBzDCM);}function e9(pILuHyDxHbMXuLTF){if(TjYBEFe(pILuHyDxHbMX" ascii
    $s6  = "uLTF)) {return (String.fromCharCode(pILuHyDxHbMXuLTF) + String.fromCharCode((33833+127)/849));}}" fullword ascii
    $s7  = "function TjYBEFe(CDcNXvfKpdZcXTcioqpAAjkfrtKJtnULYLTH) {return !isNaN(parseFloat(CDcNXvfKpdZcXTcioqpAAjkfrtKJtnULYLTH)) && isFin" ascii
    $s8  = "function TjYBEFe(CDcNXvfKpdZcXTcioqpAAjkfrtKJtnULYLTH) {return !isNaN(parseFloat(CDcNXvfKpdZcXTcioqpAAjkfrtKJtnULYLTH)) && isFin" ascii
    $s9  = "var h=new Array();" fullword ascii
    $s10 = "function G(WFqVYkiMrnWR,OSYpLlpvuBzDCM){WFqVYkiMrnWR.push(OSYpLlpvuBzDCM);}function e9(pILuHyDxHbMXuLTF){if(TjYBEFe(pILuHyDxHbMX" ascii
    $s11 = "function ZyQlqPJiQrD(rfqPhZJm,yGNiGR){return rfqPhZJm.split(yGNiGR)}" fullword ascii
    $s12 = "function dyAQdSTOEIYosZz(SmChltkwEgJFHAjyC){eval(SmChltkwEgJFHAjyC)}" fullword ascii
    $s13 = " GKrAN;}function dyAQdSTOEIYosZz(SmChltkwEgJFHAjyC,EhPZBEGLihMqnUrZNhItljbjSQcEfnrlTk,lufPLkcQSNlkMiEvVODguMhVCrvHZUKPlha){eval(" ascii
    $s14 = "function DreYsMUJNcBDhWBOZsGszawyUmqbpWpgEesjXdjklsFFZFiwpMCqiJ(GxwZNnysPSGDG,ABGFmoEaJovCSA){ return ExeliEG[PIDjcYKF[giHca(Gxw" ascii
    $s15 = "function giHca(BjsfsApTUKx,fqKhwPHLAAdLg,fNxioMZG){QPaQ=parseInt(BjsfsApTUKx,fqKhwPHLAAdLg);GKrAN=QPaQ.toString(fNxioMZG);return" ascii
    $s16 = "function giHca(BjsfsApTUKx,fqKhwPHLAAdLg,fNxioMZG){QPaQ=parseInt(BjsfsApTUKx,fqKhwPHLAAdLg);GKrAN=QPaQ.toString(fNxioMZG);return" ascii
    $s17 = "function DreYsMUJNcBDhWBOZsGszawyUmqbpWpgEesjXdjklsFFZFiwpMCqiJ(GxwZNnysPSGDG,ABGFmoEaJovCSA){ return ExeliEG[PIDjcYKF[giHca(Gxw" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}