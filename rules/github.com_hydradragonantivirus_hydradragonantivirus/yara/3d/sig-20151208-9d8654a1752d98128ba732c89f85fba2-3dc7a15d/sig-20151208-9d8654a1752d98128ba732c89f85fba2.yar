rule sig_20151208_9d8654a1752d98128ba732c89f85fba2 {
  meta:
    description = "datamaliciousorder - file 20151208_9d8654a1752d98128ba732c89f85fba2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0473c3b5eeef96d361a60e2580793b9cacb3a9150ceca6ad42ba67128383aad2"

  strings:
    $s1  = "function itGHNTG(sAkSIAFJNezSbVtykgZsSCufEscuMmkygEDD) {return !isNaN(parseFloat(sAkSIAFJNezSbVtykgZsSCufEscuMmkygEDD)) && isFin" ascii
    $s2  = "function itGHNTG(sAkSIAFJNezSbVtykgZsSCufEscuMmkygEDD) {return !isNaN(parseFloat(sAkSIAFJNezSbVtykgZsSCufEscuMmkygEDD)) && isFin" ascii
    $s3  = "push(\"34\");m.push(\"114\");m.push(\"101\");m.push(\"97\");m.push(\"109\");m.push(\"34\");m.push(\"41\");m.push(\"41\");m.push(" ascii
    $s4  = "EBJR)}function yYbGC(sNXrdUkIIuQ,MIjfUuHJAViiU,bklIwPrj){uznj=parseInt(sNXrdUkIIuQ,MIjfUuHJAViiU);VEltO=uznj.toString(bklIwPrj);" ascii
    $s5  = "function hOsiJoqOKbViCsDqyWgyeeiUuUygbjCyfuFJJEuhtdqruDACWyzOEp(NBnYduSVmFyJg,gDNVFqFbUhyXDh){ return TaVIHyvjFlwcQ[yYbGC(NBnYdu" ascii
    $s6  = "var TaVIHyvjFlwcQ=[];for(PTXEBJR=(-804+804)/641;PTXEBJR<(11174+346)/90;PTXEBJR++){TaVIHyvjFlwcQ[PTXEBJR]=String.fromCharCode(PTX" ascii
    $s7  = "function gQmoKQqHAYozLXGmF(cnCZP){bXaZzEBISIL= '';for(NKqSfDBQzlz=(-168+168)/212; NKqSfDBQzlz < (-320+470)/75; NKqSfDBQzlz++) {s" ascii
    $s8  = "function hOsiJoqOKbViCsDqyWgyeeiUuUygbjCyfuFJJEuhtdqruDACWyzOEp(NBnYduSVmFyJg,gDNVFqFbUhyXDh){ return TaVIHyvjFlwcQ[yYbGC(NBnYdu" ascii
    $s9  = "function gQmoKQqHAYozLXGmF(cnCZP){bXaZzEBISIL= '';for(NKqSfDBQzlz=(-168+168)/212; NKqSfDBQzlz < (-320+470)/75; NKqSfDBQzlz++) {s" ascii
    $s10 = "fYpcZubB[NKqSfDBQzlz]=(-258+258)/969; while(true) { if(sfYpcZubB[NKqSfDBQzlz] > cnCZP[NKqSfDBQzlz].length-(442+208)/650) { break" ascii
    $s11 = "push(\"59\");D.push(\"9\");D.push(\"32\");D.push(\"13\");D.push(\"10\");D.push(\"32\");D.push(\"32\");D.push(\"32\");D.push(\"32" ascii
    $s12 = "push(\"69\");m.push(\"120\");m.push(\"112\");m.push(\"97\");m.push(\"110\");m.push(\"100\");m.push(\"69\");m.push(\"110\");m.pus" ascii
    $s13 = "push(\"32\");m.push(\"61\");m.push(\"32\");m.push(\"87\");m.push(\"83\");m.push(\"99\");m.push(\"114\");m.push(\"105\");m.push(" ascii
    $s14 = "push(\"79\");D.push(\"121\");D.push(\"119\");D.push(\"42\");D.push(\"47\");D.push(\"51\");D.push(\"45\");D.push(\"50\");D.push(" ascii
    $s15 = "push(\"32\");D.push(\"105\");D.push(\"103\");D.push(\"113\");D.push(\"46\");D.push(\"115\");D.push(\"97\");D.push(\"118\");D.pus" ascii
    $s16 = "push(\"47\");m.push(\"42\");m.push(\"83\");m.push(\"97\");m.push(\"56\");m.push(\"108\");m.push(\"57\");m.push(\"56\");m.push(\"" ascii
    $s17 = "function EHnLhIOronU(azPxiHfV,MdDEIC){return azPxiHfV.split(MdDEIC)}" fullword ascii
    $s18 = "push(\"13\");m.push(\"10\");m.push(\"102\");m.push(\"111\");m.push(\"114\");m.push(\"32\");m.push(\"40\");m.push(\"118\");m.push" ascii
    $s19 = "+;}} return bXaZzEBISIL}" fullword ascii
    $s20 = "push(\"114\");m.push(\"117\");m.push(\"101\");m.push(\"32\");m.push(\"32\");m.push(\"44\");m.push(\"32\");m.push(\"88\");m.push(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}