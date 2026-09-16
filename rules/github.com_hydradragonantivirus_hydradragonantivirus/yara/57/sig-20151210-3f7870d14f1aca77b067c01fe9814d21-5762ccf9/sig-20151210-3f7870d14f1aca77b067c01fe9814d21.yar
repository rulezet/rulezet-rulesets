rule sig_20151210_3f7870d14f1aca77b067c01fe9814d21 {
  meta:
    description = "datamaliciousorder - file 20151210_3f7870d14f1aca77b067c01fe9814d21.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0732ae5f617b92ab667ecd85ca684b203e75b6abf748fa8b6011c5545bec9aeb"

  strings:
    $s1  = "function JYeDcex(fiDuRMxkEvDXUonGxFyBwtRXJLbgwmspMBUe) {return !isNaN(parseFloat(fiDuRMxkEvDXUonGxFyBwtRXJLbgwmspMBUe)) && isFin" ascii
    $s2  = "function JYeDcex(fiDuRMxkEvDXUonGxFyBwtRXJLbgwmspMBUe) {return !isNaN(parseFloat(fiDuRMxkEvDXUonGxFyBwtRXJLbgwmspMBUe)) && isFin" ascii
    $s3  = "function WrzGq(ztHjcQuTgkG,BeQxjqseWpyhf,fQidEWpH){ioWI=parseInt(ztHjcQuTgkG,BeQxjqseWpyhf);fMJdq=ioWI.toString(fQidEWpH);return" ascii
    $s4  = "MUKGHjJf[oSrNzsiElqQ]=(-391+391)/50; while(true) { if(hMUKGHjJf[oSrNzsiElqQ] > HfnFr[oSrNzsiElqQ].length-(-864+878)/14) { break;" ascii
    $s5  = "function WrzGq(ztHjcQuTgkG,BeQxjqseWpyhf,fQidEWpH){ioWI=parseInt(ztHjcQuTgkG,BeQxjqseWpyhf);fMJdq=ioWI.toString(fQidEWpH);return" ascii
    $s6  = ";}} return VUFdTNMILAE}" fullword ascii
    $s7  = "ogFEiid=(-380+380)/803;while(true){if(ogFEiid>=(51204+508)/404){break;}GQXmlZgdhxXnw[ogFEiid]=String.fromCharCode(ogFEiid);ogFEi" ascii
    $s8  = "function GOkWssryWlqgWHncY(HfnFr){VUFdTNMILAE= '';for(oSrNzsiElqQ=(-797+797)/419; oSrNzsiElqQ < (627+503)/565; oSrNzsiElqQ++) {h" ascii
    $s9  = "function tgYgDUUTOByHzTVnpFGMvVqcgzyOlsRSPHhfntAESMOKxPVhzUaRwb(BVZbWGlpqnICv,AJjFWQAhiNZtCH){ return GQXmlZgdhxXnw[WrzGq(BVZbWG" ascii
    $s10 = "function GOkWssryWlqgWHncY(HfnFr){VUFdTNMILAE= '';for(oSrNzsiElqQ=(-797+797)/419; oSrNzsiElqQ < (627+503)/565; oSrNzsiElqQ++) {h" ascii
    $s11 = " fMJdq;}function HyRZSsBJTUmEnTd(suJOPPVSelCEsnqpg){eval(suJOPPVSelCEsnqpg)}" fullword ascii
    $s12 = "ogFEiid=(-380+380)/803;while(true){if(ogFEiid>=(51204+508)/404){break;}GQXmlZgdhxXnw[ogFEiid]=String.fromCharCode(ogFEiid);ogFEi" ascii
    $s13 = "function tgYgDUUTOByHzTVnpFGMvVqcgzyOlsRSPHhfntAESMOKxPVhzUaRwb(BVZbWGlpqnICv,AJjFWQAhiNZtCH){ return GQXmlZgdhxXnw[WrzGq(BVZbWG" ascii
    $s14 = "function VGsuCSVfeaH(IIdpGPSm,iRwYHY){return IIdpGPSm.split(iRwYHY)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}