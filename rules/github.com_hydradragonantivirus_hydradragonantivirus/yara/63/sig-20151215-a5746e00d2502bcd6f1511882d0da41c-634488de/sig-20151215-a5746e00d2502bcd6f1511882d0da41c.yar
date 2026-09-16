rule sig_20151215_a5746e00d2502bcd6f1511882d0da41c {
  meta:
    description = "datamaliciousorder - file 20151215_a5746e00d2502bcd6f1511882d0da41c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2678237ed2ef9aae6d5c9e7dfa7414df82c58e55029759cb5c39f2e59eb9380"

  strings:
    $s1  = "Math.pow(Math.cos(898), 2) - 1)); while(true) { if(qFlCxClJl[jsHBCtyNqHA] > hhBXT[jsHBCtyNqHA].length-(86+675)/761) { break; } i" ascii
    $s2  = "(Math.cos(777), 2) - 1)));} qFlCxClJl[jsHBCtyNqHA]++;}} return SgcdWFEXEHA}" fullword ascii
    $s3  = "function TSSCEpDjXPaaTRguj(hhBXT){SgcdWFEXEHA= j[1779];for(jsHBCtyNqHA=Math.round((Math.pow(Math.sin(857), 2) + Math.pow(Math.co" ascii
    $s4  = "function TSSCEpDjXPaaTRguj(hhBXT){SgcdWFEXEHA= j[1779];for(jsHBCtyNqHA=Math.round((Math.pow(Math.sin(857), 2) + Math.pow(Math.co" ascii
    $s5  = "cjis)) {return (String.fromCharCode(SSCckpebnjWNcjis) + String.fromCharCode((6736+564)/100));}}" fullword ascii
    $s6  = "function ODngd(nRUnrLSdOeQ,OEmSmcLcYDMcD,AjYsptdo){wTWI=parseInt(nRUnrLSdOeQ,OEmSmcLcYDMcD);eIuZn=wTWI.toString(AjYsptdo);return" ascii
    $s7  = "var j=new Array();" fullword ascii
    $s8  = "function dpkscSVRymCzrnctAEQIWvlsRqxoKuDEwfAZNralaCGGATrDJDggJY(megbwqpCusdPn,niPlvQCqMPruAi){ return vlcCtLf[uMvQxTJA[ODngd(meg" ascii
    $s9  = "function WtemhQiQxgq(kyGiqAXp,qHMJZQ){return kyGiqAXp.split(qHMJZQ)}" fullword ascii
    $s10 = "function dpkscSVRymCzrnctAEQIWvlsRqxoKuDEwfAZNralaCGGATrDJDggJY(megbwqpCusdPn,niPlvQCqMPruAi){ return vlcCtLf[uMvQxTJA[ODngd(meg" ascii
    $s11 = "function o(DmheheouVtCu,WnQVYCMESAdtWX){DmheheouVtCu.push(WnQVYCMESAdtWX);}function d8(SSCckpebnjWNcjis){if(LCANPhv(SSCckpebnjWN" ascii
    $s12 = "function LCANPhv(kiLIOESylubxhnXUxKZzjUpeYGqEepQuNcZC) {return !isNaN(parseFloat(kiLIOESylubxhnXUxKZzjUpeYGqEepQuNcZC)) && isFin" ascii
    $s13 = "function ODngd(nRUnrLSdOeQ,OEmSmcLcYDMcD,AjYsptdo){wTWI=parseInt(nRUnrLSdOeQ,OEmSmcLcYDMcD);eIuZn=wTWI.toString(AjYsptdo);return" ascii
    $s14 = "function LCANPhv(kiLIOESylubxhnXUxKZzjUpeYGqEepQuNcZC) {return !isNaN(parseFloat(kiLIOESylubxhnXUxKZzjUpeYGqEepQuNcZC)) && isFin" ascii
    $s15 = "function o(DmheheouVtCu,WnQVYCMESAdtWX){DmheheouVtCu.push(WnQVYCMESAdtWX);}function d8(SSCckpebnjWNcjis){if(LCANPhv(SSCckpebnjWN" ascii
    $s16 = " eIuZn;}function iLcAYHysTYCEFvZ(AkfWwHMgoGXeHDOWk,kgtGLlzWWddezxUoKiPefbVrGWXyhRarsk,GosywXiXJSJHVdBNEzRuWdeXhFyeisiPzCe){eval(" ascii
    $s17 = "function iLcAYHysTYCEFvZ(AkfWwHMgoGXeHDOWk){eval(AkfWwHMgoGXeHDOWk)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}