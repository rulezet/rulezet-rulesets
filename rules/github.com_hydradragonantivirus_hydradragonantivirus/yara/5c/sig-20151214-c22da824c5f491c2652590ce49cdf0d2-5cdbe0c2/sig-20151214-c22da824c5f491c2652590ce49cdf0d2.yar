rule sig_20151214_c22da824c5f491c2652590ce49cdf0d2 {
  meta:
    description = "datamaliciousorder - file 20151214_c22da824c5f491c2652590ce49cdf0d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06e7aabdb11783f2c8d89e61d4fbac9b115e5871aeecc189c95bc0c5a39a1653"

  strings:
    $s1  = "Math.pow(Math.cos(978), 2) - 1)); while(true) { if(cmzkYkQpP[eqjLiwhMtDH] > xTgat[eqjLiwhMtDH].length-(184+431)/615) { break; } " ascii
    $s2  = "function UtRaWVvzymXrQcNjy(xTgat){NkDFPKoPIXp= A[1816];for(eqjLiwhMtDH=Math.round((Math.pow(Math.sin(609), 2) + Math.pow(Math.co" ascii
    $s3  = ".pow(Math.cos(503), 2) - 1)));} cmzkYkQpP[eqjLiwhMtDH]++;}} return NkDFPKoPIXp}" fullword ascii
    $s4  = "JiEzbzOhUWUOzaNyNOtZWFtqjsyUdNVymTpn([xTgat[eqjLiwhMtDH][cmzkYkQpP[eqjLiwhMtDH]]], Math.round((Math.pow(Math.sin(503), 2) + Math" ascii
    $s5  = "function UtRaWVvzymXrQcNjy(xTgat){NkDFPKoPIXp= A[1816];for(eqjLiwhMtDH=Math.round((Math.pow(Math.sin(609), 2) + Math.pow(Math.co" ascii
    $s6  = "qUdc)) {return (String.fromCharCode(jvwpHFLImzfdqUdc) + String.fromCharCode((3193+766)/107));}}" fullword ascii
    $s7  = "function K(oHnRMqYvgUHo,jXmFZpuSKBRcsb){oHnRMqYvgUHo.push(jXmFZpuSKBRcsb);}function Z9(jvwpHFLImzfdqUdc){if(vdPislp(jvwpHFLImzfd" ascii
    $s8  = "function vdPislp(kMcLGzdUIzwWfdkgqwkRKFRyvUdWSYaMKpHP) {return !isNaN(parseFloat(kMcLGzdUIzwWfdkgqwkRKFRyvUdWSYaMKpHP)) && isFin" ascii
    $s9  = "function vdPislp(kMcLGzdUIzwWfdkgqwkRKFRyvUdWSYaMKpHP) {return !isNaN(parseFloat(kMcLGzdUIzwWfdkgqwkRKFRyvUdWSYaMKpHP)) && isFin" ascii
    $s10 = "function TMKouIWLnuZZWvEmDAJiEzbzOhUWUOzaNyNOtZWFtqjsyUdNVymTpn(tzDnwoBENMZbY,dRIatOKxZTSQoL){ return kYbtOcS[RgxWxrKO[hsKlT(tzD" ascii
    $s11 = "var A=new Array();" fullword ascii
    $s12 = "function OUYRoAKWjsUwbpQ(tYuhoZCgSfLkekFCv){eval(tYuhoZCgSfLkekFCv)}" fullword ascii
    $s13 = "function TMKouIWLnuZZWvEmDAJiEzbzOhUWUOzaNyNOtZWFtqjsyUdNVymTpn(tzDnwoBENMZbY,dRIatOKxZTSQoL){ return kYbtOcS[RgxWxrKO[hsKlT(tzD" ascii
    $s14 = "function K(oHnRMqYvgUHo,jXmFZpuSKBRcsb){oHnRMqYvgUHo.push(jXmFZpuSKBRcsb);}function Z9(jvwpHFLImzfdqUdc){if(vdPislp(jvwpHFLImzfd" ascii
    $s15 = "function mXfJXaTgRfl(VnmFxvXu,tTDIgn){return VnmFxvXu.split(tTDIgn)}" fullword ascii
    $s16 = "function hsKlT(kwKFrfebtPO,NwIvSzKdtHtLx,gWsESLqe){HLbX=parseInt(kwKFrfebtPO,NwIvSzKdtHtLx);mqzCn=HLbX.toString(gWsESLqe);return" ascii
    $s17 = "function hsKlT(kwKFrfebtPO,NwIvSzKdtHtLx,gWsESLqe){HLbX=parseInt(kwKFrfebtPO,NwIvSzKdtHtLx);mqzCn=HLbX.toString(gWsESLqe);return" ascii
    $s18 = " mqzCn;}function OUYRoAKWjsUwbpQ(tYuhoZCgSfLkekFCv,EFqbNAxQdvqACaLHIZBbSdMFqNhUwbKPDC,bOzdffzbPyknyAgOWePvqwNOckRatUQQJkg){eval(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}