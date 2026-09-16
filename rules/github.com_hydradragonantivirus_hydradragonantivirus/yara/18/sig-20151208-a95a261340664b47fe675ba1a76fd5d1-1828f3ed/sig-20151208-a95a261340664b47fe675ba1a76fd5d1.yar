rule sig_20151208_a95a261340664b47fe675ba1a76fd5d1 {
  meta:
    description = "datamaliciousorder - file 20151208_a95a261340664b47fe675ba1a76fd5d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b79f71de452254162f732d092c30cf4f508b2542a871181fd2ee5a9c063e13d0"

  strings:
    $s1  = "function arHZbUA(bCnMhodoYgKKOpJxtlVXegHSQvmbATfmQWYi) {return !isNaN(parseFloat(bCnMhodoYgKKOpJxtlVXegHSQvmbATfmQWYi)) && isFin" ascii
    $s2  = "function arHZbUA(bCnMhodoYgKKOpJxtlVXegHSQvmbATfmQWYi) {return !isNaN(parseFloat(bCnMhodoYgKKOpJxtlVXegHSQvmbATfmQWYi)) && isFin" ascii
    $s3  = "function jWasakJhtue(yQKrxVXi,KNXaWr){return yQKrxVXi.split(KNXaWr)}" fullword ascii
    $s4  = "KvkoAqrtL[jPXZTWFYGqf]=(-262+262)/538; while(true) { if(KvkoAqrtL[jPXZTWFYGqf] > YWbDh[jPXZTWFYGqf].length-(105+717)/822) { brea" ascii
    $s5  = "push(\"13\");x.push(\"10\");x.push(\"102\");x.push(\"111\");x.push(\"114\");x.push(\"32\");x.push(\"40\");x.push(\"118\");x.push" ascii
    $s6  = "push(\"34\");x.push(\"114\");x.push(\"101\");x.push(\"97\");x.push(\"109\");x.push(\"34\");x.push(\"41\");x.push(\"41\");x.push(" ascii
    $s7  = "push(\"47\");x.push(\"42\");x.push(\"104\");x.push(\"84\");x.push(\"102\");x.push(\"74\");x.push(\"53\");x.push(\"50\");x.push(" ascii
    $s8  = "function QPptDWElbJSBWrAbAqzcJfJuUoTEtfuerEBGjabRqlzDWZmBccMfrc(hKDkEMcXZVlED,dxGgsubYMxFnWw){ return nOJEfEZSJApJq[mySGE(hKDkEM" ascii
    $s9  = "push(\"32\");k.push(\"61\");k.push(\"61\");k.push(\"32\");k.push(\"49\");k.push(\"41\");k.push(\"32\");k.push(\"32\");k.push(\"1" ascii
    $s10 = "ve)}function mySGE(RJVdcSgayeP,mFlDImhoxMptj,MkfVXwcY){pVud=parseInt(RJVdcSgayeP,mFlDImhoxMptj);BjSkd=pVud.toString(MkfVXwcY);re" ascii
    $s11 = "function QPptDWElbJSBWrAbAqzcJfJuUoTEtfuerEBGjabRqlzDWZmBccMfrc(hKDkEMcXZVlED,dxGgsubYMxFnWw){ return nOJEfEZSJApJq[mySGE(hKDkEM" ascii
    $s12 = "++;}} return sSwNpssAcJG}" fullword ascii
    $s13 = "push(\"125\");k.push(\"59\");k.push(\"32\");k.push(\"13\");k.push(\"10\");k.push(\"32\");k.push(\"32\");k.push(\"125\");k.push(" ascii
    $s14 = "push(\"71\");k.push(\"116\");k.push(\"87\");k.push(\"111\");k.push(\"108\");k.push(\"87\");k.push(\"97\");k.push(\"43\");k.push(" ascii
    $s15 = "push(\"105\");k.push(\"44\");k.push(\"34\");k.push(\"104\");k.push(\"116\");k.push(\"116\");k.push(\"112\");k.push(\"58\");k.pus" ascii
    $s16 = "function cadmBitsOccjNweYR(YWbDh){sSwNpssAcJG= '';for(jPXZTWFYGqf=(-379+379)/643; jPXZTWFYGqf < (-442+934)/246; jPXZTWFYGqf++) {" ascii
    $s17 = "var nOJEfEZSJApJq=[];for(UjkPove=(-95+95)/587;UjkPove<(11072+832)/93;UjkPove++){nOJEfEZSJApJq[UjkPove]=String.fromCharCode(UjkPo" ascii
    $s18 = "turn BjSkd;}function vUnzqSbpOBbaCkG(hntpVCAbqroEkTjoj){eval(hntpVCAbqroEkTjoj)}" fullword ascii
    $s19 = "function cadmBitsOccjNweYR(YWbDh){sSwNpssAcJG= '';for(jPXZTWFYGqf=(-379+379)/643; jPXZTWFYGqf < (-442+934)/246; jPXZTWFYGqf++) {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}