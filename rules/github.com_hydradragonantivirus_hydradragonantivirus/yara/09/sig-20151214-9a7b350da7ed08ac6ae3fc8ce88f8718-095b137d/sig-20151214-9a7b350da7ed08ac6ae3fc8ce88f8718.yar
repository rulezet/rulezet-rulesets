rule sig_20151214_9a7b350da7ed08ac6ae3fc8ce88f8718 {
  meta:
    description = "datamaliciousorder - file 20151214_9a7b350da7ed08ac6ae3fc8ce88f8718.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7bf3c3c11f8fc88079aac6bf07195f8710289d259f4c28216fac171acef59d3"

  strings:
    $s1  = "th.pow(Math.cos(441), 2) - 1)); while(true) { if(WDhJJFDYu[nWmFanhzZTO] > LIhcO[nWmFanhzZTO].length-(47+542)/589) { break; } if " ascii
    $s2  = "(Math.cos(402), 2) - 1)));} WDhJJFDYu[nWmFanhzZTO]++;}} return lPBwgbaLSPh}" fullword ascii
    $s3  = "function ftCUahQgmKZzHpHTx(LIhcO){lPBwgbaLSPh= D[1764];for(nWmFanhzZTO=Math.round((Math.pow(Math.sin(688), 2) + Math.pow(Math.co" ascii
    $s4  = "function ftCUahQgmKZzHpHTx(LIhcO){lPBwgbaLSPh= D[1764];for(nWmFanhzZTO=Math.round((Math.pow(Math.sin(688), 2) + Math.pow(Math.co" ascii
    $s5  = "function z(GGWbMPtXLqGH,XVqWEoJeHnRbCW){GGWbMPtXLqGH.push(XVqWEoJeHnRbCW);}function y3(raWooVBCuVdLalCo){if(EakMNxy(raWooVBCuVdL" ascii
    $s6  = "alCo)) {return (String.fromCharCode(raWooVBCuVdLalCo) + String.fromCharCode((45682+756)/749));}}" fullword ascii
    $s7  = "function EakMNxy(tlgwiVzdZfHQxvkcNseqVtKAUpYoNnYjgVev) {return !isNaN(parseFloat(tlgwiVzdZfHQxvkcNseqVtKAUpYoNnYjgVev)) && isFin" ascii
    $s8  = "function EakMNxy(tlgwiVzdZfHQxvkcNseqVtKAUpYoNnYjgVev) {return !isNaN(parseFloat(tlgwiVzdZfHQxvkcNseqVtKAUpYoNnYjgVev)) && isFin" ascii
    $s9  = "function vzxhrqLiNHIJvHC(XAoJtFKudfbIjCcrk){eval(XAoJtFKudfbIjCcrk)}" fullword ascii
    $s10 = "function EpeEM(gblpdORWLFE,nKBrhaKfeHpfy,wEGVLtrb){OmFL=parseInt(gblpdORWLFE,nKBrhaKfeHpfy);qeYnE=OmFL.toString(wEGVLtrb);return" ascii
    $s11 = "function xzxanjGvMyZ(IKWlGXEJ,sZNpRB){return IKWlGXEJ.split(sZNpRB)}" fullword ascii
    $s12 = " qeYnE;}function vzxhrqLiNHIJvHC(XAoJtFKudfbIjCcrk,wRIImFMSiDppnLUuLfFjXMOjNlyuXHOGhc,LcNhyxLXwnBrkpWktHFtexHxsMTBNkofOQE){eval(" ascii
    $s13 = "function EpeEM(gblpdORWLFE,nKBrhaKfeHpfy,wEGVLtrb){OmFL=parseInt(gblpdORWLFE,nKBrhaKfeHpfy);qeYnE=OmFL.toString(wEGVLtrb);return" ascii
    $s14 = "function z(GGWbMPtXLqGH,XVqWEoJeHnRbCW){GGWbMPtXLqGH.push(XVqWEoJeHnRbCW);}function y3(raWooVBCuVdLalCo){if(EakMNxy(raWooVBCuVdL" ascii
    $s15 = "function vKTZNbcyooSTYSLxYndlPxWAfGgOlrqCxBuWelAvbYXqLbREHHjiBn(JhPPpENtAbBfC,WhuZWNzlHaBHyW){ return rRhYXdk[QpPjFnDU[EpeEM(JhP" ascii
    $s16 = "function vKTZNbcyooSTYSLxYndlPxWAfGgOlrqCxBuWelAvbYXqLbREHHjiBn(JhPPpENtAbBfC,WhuZWNzlHaBHyW){ return rRhYXdk[QpPjFnDU[EpeEM(JhP" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}