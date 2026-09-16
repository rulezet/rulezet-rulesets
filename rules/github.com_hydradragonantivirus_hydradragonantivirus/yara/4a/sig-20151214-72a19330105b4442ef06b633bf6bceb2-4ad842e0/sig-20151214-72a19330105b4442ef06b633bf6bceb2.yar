rule sig_20151214_72a19330105b4442ef06b633bf6bceb2 {
  meta:
    description = "datamaliciousorder - file 20151214_72a19330105b4442ef06b633bf6bceb2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79fd75e86e152fc4ecd539e83c804eb19ad941c49a91f44b336f1474bc54b57c"

  strings:
    $s1  = "1), 2) - 1)); zUOnbCeAcMQ < (774+538)/656; zUOnbCeAcMQ++) {usREGtfvU[zUOnbCeAcMQ]=Math.round((Math.pow(Math.sin(803), 2) + Math." ascii
    $s2  = "(Math.cos(980), 2) - 1)));} usREGtfvU[zUOnbCeAcMQ]++;}} return VHUZAlEFaCG}" fullword ascii
    $s3  = "function ZlSqTyBHAcqsSNSdD(TlYgf){VHUZAlEFaCG= a[1732];for(zUOnbCeAcMQ=Math.round((Math.pow(Math.sin(1), 2) + Math.pow(Math.cos(" ascii
    $s4  = "pow(Math.cos(803), 2) - 1)); while(true) { if(usREGtfvU[zUOnbCeAcMQ] > TlYgf[zUOnbCeAcMQ].length-(-219+885)/666) { break; } if (" ascii
    $s5  = "function ZlSqTyBHAcqsSNSdD(TlYgf){VHUZAlEFaCG= a[1732];for(zUOnbCeAcMQ=Math.round((Math.pow(Math.sin(1), 2) + Math.pow(Math.cos(" ascii
    $s6  = "function r(cuGKnSXmuoyZ,MhBpOpZMhyDUnA){cuGKnSXmuoyZ.push(MhBpOpZMhyDUnA);}function r7(DHosapWXovpXxDRK){if(xqOsPVX(DHosapWXovpX" ascii
    $s7  = "xDRK)) {return (String.fromCharCode(DHosapWXovpXxDRK) + String.fromCharCode((28988+272)/380));}}" fullword ascii
    $s8  = "function xqOsPVX(joThGNjyyhkIsolZWzuExHAHTlCjdxiCMUvr) {return !isNaN(parseFloat(joThGNjyyhkIsolZWzuExHAHTlCjdxiCMUvr)) && isFin" ascii
    $s9  = "function xqOsPVX(joThGNjyyhkIsolZWzuExHAHTlCjdxiCMUvr) {return !isNaN(parseFloat(joThGNjyyhkIsolZWzuExHAHTlCjdxiCMUvr)) && isFin" ascii
    $s10 = "var a=new Array();" fullword ascii
    $s11 = "function r(cuGKnSXmuoyZ,MhBpOpZMhyDUnA){cuGKnSXmuoyZ.push(MhBpOpZMhyDUnA);}function r7(DHosapWXovpXxDRK){if(xqOsPVX(DHosapWXovpX" ascii
    $s12 = "function aavxZiBlhiYHpFj(jBaRwoscdkrPiaahA){eval(jBaRwoscdkrPiaahA)}" fullword ascii
    $s13 = "function OnQsp(BYlNjlLGUQj,PjTmgDLsurSUH,lNMGfVEg){xmBs=parseInt(BYlNjlLGUQj,PjTmgDLsurSUH);fXoIC=xmBs.toString(lNMGfVEg);return" ascii
    $s14 = " fXoIC;}function aavxZiBlhiYHpFj(jBaRwoscdkrPiaahA,IHMotNxvxYhwZlGKNJEooGwvJVXGRimKtf,yMYRWpmbwzqIfhyPptbDJHkChjAyyXTkzjf){eval(" ascii
    $s15 = "function WqmxTuZIkJk(yjauMrpE,qbxOvk){return yjauMrpE.split(qbxOvk)}" fullword ascii
    $s16 = "function OnQsp(BYlNjlLGUQj,PjTmgDLsurSUH,lNMGfVEg){xmBs=parseInt(BYlNjlLGUQj,PjTmgDLsurSUH);fXoIC=xmBs.toString(lNMGfVEg);return" ascii
    $s17 = "function pSMndvrMIaQqpPlzssJOSgpJAmhNqDkKWBsmiLUJqtlWMUgRUkLzER(mgVGoHPyzDkWs,HzDsZbgeieErnA){ return DwTxxlL[kHfeZwXm[OnQsp(mgV" ascii
    $s18 = "function pSMndvrMIaQqpPlzssJOSgpJAmhNqDkKWBsmiLUJqtlWMUgRUkLzER(mgVGoHPyzDkWs,HzDsZbgeieErnA){ return DwTxxlL[kHfeZwXm[OnQsp(mgV" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}