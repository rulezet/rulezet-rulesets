rule sig_20151214_66ef4ba4996aa04381908c7f68e4e5bc {
  meta:
    description = "datamaliciousorder - file 20151214_66ef4ba4996aa04381908c7f68e4e5bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19325c60339f3b3aab510dbf93b72586dc60833383692789b99a0f447cfd60a6"

  strings:
    $s1  = "ath.pow(Math.cos(63), 2) - 1)); while(true) { if(vuwseAfiv[HRcgxhYiUfI] > lfjLr[HRcgxhYiUfI].length-(-116+595)/479) { break; } i" ascii
    $s2  = ".pow(Math.cos(555), 2) - 1)));} vuwseAfiv[HRcgxhYiUfI]++;}} return gBmVdzQlWKb}" fullword ascii
    $s3  = "function ZNDXPEfebBCzmhfde(lfjLr){gBmVdzQlWKb= F[1720];for(HRcgxhYiUfI=Math.round((Math.pow(Math.sin(757), 2) + Math.pow(Math.co" ascii
    $s4  = "function ZNDXPEfebBCzmhfde(lfjLr){gBmVdzQlWKb= F[1720];for(HRcgxhYiUfI=Math.round((Math.pow(Math.sin(757), 2) + Math.pow(Math.co" ascii
    $s5  = "hvZcTIwjQiLDUEEuiZgLqYCDmNumamMsRiVB([lfjLr[HRcgxhYiUfI][vuwseAfiv[HRcgxhYiUfI]]], Math.round((Math.pow(Math.sin(555), 2) + Math" ascii
    $s6  = "NMYv)) {return (String.fromCharCode(zOyAQxvSMUxgNMYv) + String.fromCharCode((36791+697)/568));}}" fullword ascii
    $s7  = "function d(mVFesfKCpGlS,IuLYVRSRHabShi){mVFesfKCpGlS.push(IuLYVRSRHabShi);}function f3(zOyAQxvSMUxgNMYv){if(zAAxZaM(zOyAQxvSMUxg" ascii
    $s8  = "function zAAxZaM(UApMlKAphNmMQauLoDLnhMSTzPdihAGRkYik) {return !isNaN(parseFloat(UApMlKAphNmMQauLoDLnhMSTzPdihAGRkYik)) && isFin" ascii
    $s9  = "function zAAxZaM(UApMlKAphNmMQauLoDLnhMSTzPdihAGRkYik) {return !isNaN(parseFloat(UApMlKAphNmMQauLoDLnhMSTzPdihAGRkYik)) && isFin" ascii
    $s10 = "function TmDjYeuILkB(nXTtXJUw,VKDAcm){return nXTtXJUw.split(VKDAcm)}" fullword ascii
    $s11 = "function mKiOwicgNTWRbie(rplRFbwKnTOWIdjJq){eval(rplRFbwKnTOWIdjJq)}" fullword ascii
    $s12 = "function LncbR(apInPpwGzua,rfxHJyArnSMQq,talguIBZ){TEQw=parseInt(apInPpwGzua,rfxHJyArnSMQq);OoqVe=TEQw.toString(talguIBZ);return" ascii
    $s13 = "function sciWcTuwgoTvytUhmVhvZcTIwjQiLDUEEuiZgLqYCDmNumamMsRiVB(QbCylgaPmKGlh,jhkQBHBdVeAmAZ){ return trdySFv[PhTTOdrg[LncbR(QbC" ascii
    $s14 = "var F=new Array();" fullword ascii
    $s15 = "function sciWcTuwgoTvytUhmVhvZcTIwjQiLDUEEuiZgLqYCDmNumamMsRiVB(QbCylgaPmKGlh,jhkQBHBdVeAmAZ){ return trdySFv[PhTTOdrg[LncbR(QbC" ascii
    $s16 = "function d(mVFesfKCpGlS,IuLYVRSRHabShi){mVFesfKCpGlS.push(IuLYVRSRHabShi);}function f3(zOyAQxvSMUxgNMYv){if(zAAxZaM(zOyAQxvSMUxg" ascii
    $s17 = " OoqVe;}function mKiOwicgNTWRbie(rplRFbwKnTOWIdjJq,oCpYHnahuXahLgbjdcywJIHjVJRQLUmnHW,ABhhyBnnOXonYKDCsPeBaBrVmICLpbtuTnH){eval(" ascii
    $s18 = "function LncbR(apInPpwGzua,rfxHJyArnSMQq,talguIBZ){TEQw=parseInt(apInPpwGzua,rfxHJyArnSMQq);OoqVe=TEQw.toString(talguIBZ);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}