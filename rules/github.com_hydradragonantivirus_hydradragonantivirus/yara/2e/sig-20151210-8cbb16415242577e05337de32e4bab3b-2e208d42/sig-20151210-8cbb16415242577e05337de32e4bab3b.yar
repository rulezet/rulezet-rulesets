rule sig_20151210_8cbb16415242577e05337de32e4bab3b {
  meta:
    description = "datamaliciousorder - file 20151210_8cbb16415242577e05337de32e4bab3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89949787d979d3e29c2f9a3c4038e4bdda6cbb0f6c3e3ad63c7db2397a8d589c"

  strings:
    $s1  = "function sMpoBEE(RxqxsXpAFzaeZJfixRvlPWmYeImaZkHPgvdm) {return !isNaN(parseFloat(RxqxsXpAFzaeZJfixRvlPWmYeImaZkHPgvdm)) && isFin" ascii
    $s2  = "function sMpoBEE(RxqxsXpAFzaeZJfixRvlPWmYeImaZkHPgvdm) {return !isNaN(parseFloat(RxqxsXpAFzaeZJfixRvlPWmYeImaZkHPgvdm)) && isFin" ascii
    $s3  = "function DNqqS(jAQLzZXMxAr,zMWVwJhNCLYiK,NhIWJGUB){Atep=parseInt(jAQLzZXMxAr,zMWVwJhNCLYiK);Bshgq=Atep.toString(NhIWJGUB);return" ascii
    $s4  = "++;}} return aaFwdORTtVF}" fullword ascii
    $s5  = "function EJiWAHuWNEk(xiVIpTDy,UYwIeV){return xiVIpTDy.split(UYwIeV)}" fullword ascii
    $s6  = "function DNqqS(jAQLzZXMxAr,zMWVwJhNCLYiK,NhIWJGUB){Atep=parseInt(jAQLzZXMxAr,zMWVwJhNCLYiK);Bshgq=Atep.toString(NhIWJGUB);return" ascii
    $s7  = "UhHQZwB=(-195+195)/748;while(true){if(UhHQZwB>=(90997+139)/712){break;}ZpnrXfPTcdyvJ[UhHQZwB]=String.fromCharCode(UhHQZwB);UhHQZ" ascii
    $s8  = "UhHQZwB=(-195+195)/748;while(true){if(UhHQZwB>=(90997+139)/712){break;}ZpnrXfPTcdyvJ[UhHQZwB]=String.fromCharCode(UhHQZwB);UhHQZ" ascii
    $s9  = "function geROJyGzwJEhrRqbepgXBCJewAiHRiHDdsobuteeodZGUpZDmlyjXx(XKNPomyMjGXEX,aNklXWVxHpLbON){ return ZpnrXfPTcdyvJ[DNqqS(XKNPom" ascii
    $s10 = "function geROJyGzwJEhrRqbepgXBCJewAiHRiHDdsobuteeodZGUpZDmlyjXx(XKNPomyMjGXEX,aNklXWVxHpLbON){ return ZpnrXfPTcdyvJ[DNqqS(XKNPom" ascii
    $s11 = " Bshgq;}function FNKiuCEUdqGXzQx(PObExajNnCYkXwhKm){eval(PObExajNnCYkXwhKm)}" fullword ascii
    $s12 = "HWNwPpSl[XerPfFuVqEZ]=(-105+105)/217; while(true) { if(wHWNwPpSl[XerPfFuVqEZ] > llEgQ[XerPfFuVqEZ].length-(-388+422)/34) { break" ascii
    $s13 = "function UfeLVwAqGlZjgkMCA(llEgQ){aaFwdORTtVF= '';for(XerPfFuVqEZ=(-833+833)/361; XerPfFuVqEZ < (362+936)/649; XerPfFuVqEZ++) {w" ascii
    $s14 = "function UfeLVwAqGlZjgkMCA(llEgQ){aaFwdORTtVF= '';for(XerPfFuVqEZ=(-833+833)/361; XerPfFuVqEZ < (362+936)/649; XerPfFuVqEZ++) {w" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}