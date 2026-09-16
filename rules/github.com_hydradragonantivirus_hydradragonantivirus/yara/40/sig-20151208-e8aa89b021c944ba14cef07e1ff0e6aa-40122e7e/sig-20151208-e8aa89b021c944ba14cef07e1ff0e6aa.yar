rule sig_20151208_e8aa89b021c944ba14cef07e1ff0e6aa {
  meta:
    description = "datamaliciousorder - file 20151208_e8aa89b021c944ba14cef07e1ff0e6aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "487b557a3be507f43a13ea8078c30ae315931b81c23f47f4f205a0ba5b9a5405"

  strings:
    $s1  = "function TvbhmsPyfwg(WLGqTbev,qPNKzp){return WLGqTbev.split(qPNKzp)}" fullword ascii
    $s2  = "function DwtHGEy(wscXkHxPTXymOsCbDKnzSrhrLGxhzchkfZVD) {return !isNaN(parseFloat(wscXkHxPTXymOsCbDKnzSrhrLGxhzchkfZVD)) && isFin" ascii
    $s3  = "function DwtHGEy(wscXkHxPTXymOsCbDKnzSrhrLGxhzchkfZVD) {return !isNaN(parseFloat(wscXkHxPTXymOsCbDKnzSrhrLGxhzchkfZVD)) && isFin" ascii
    $s4  = "push(\"32\");k.push(\"74\");k.push(\"98\");k.push(\"46\");k.push(\"47\");k.push(\"42\");k.push(\"100\");k.push(\"50\");k.push(\"" ascii
    $s5  = "push(\"79\");u.push(\"98\");u.push(\"41\");u.push(\"59\");u.push(\"13\");u.push(\"10\");u.push(\"118\");u.push(\"97\");u.push(\"" ascii
    $s6  = "function zrpwJZBxmKSMxGEZM(BjtNo){cTCZfGxCkdV= '';for(plKaDHDrrzr=(-909+909)/649; plKaDHDrrzr < (623+397)/510; plKaDHDrrzr++) {z" ascii
    $s7  = ");return JZGoq;}function CcPzMcYHugOtpoo(HlSyfafoWhPASCCZA){eval(HlSyfafoWhPASCCZA)}" fullword ascii
    $s8  = "function rOwgBvOIauaAWqaiBusEYXpNPsJMBSeplndcLFFGyWXSQrkYoHXONZ(MJOVfPsWrqSIf,loqcujdLqSOTMt){ return QJNDluObGgWSz[zlHmg(MJOVfP" ascii
    $s9  = "OZTHam)}function zlHmg(ExvsHnSqgrS,yvnPWKGcbWZRO,FHzoytRQ){YWTw=parseInt(ExvsHnSqgrS,yvnPWKGcbWZRO);JZGoq=YWTw.toString(FHzoytRQ" ascii
    $s10 = ";}} return cTCZfGxCkdV}" fullword ascii
    $s11 = "push(\"32\");k.push(\"32\");k.push(\"32\");k.push(\"32\");k.push(\"32\");k.push(\"32\");k.push(\"82\");k.push(\"121\");k.push(\"" ascii
    $s12 = "push(\"32\");u.push(\"116\");u.push(\"114\");u.push(\"117\");u.push(\"101\");u.push(\"32\");u.push(\"32\");u.push(\"44\");u.push" ascii
    $s13 = "function zrpwJZBxmKSMxGEZM(BjtNo){cTCZfGxCkdV= '';for(plKaDHDrrzr=(-909+909)/649; plKaDHDrrzr < (623+397)/510; plKaDHDrrzr++) {z" ascii
    $s14 = "function rOwgBvOIauaAWqaiBusEYXpNPsJMBSeplndcLFFGyWXSQrkYoHXONZ(MJOVfPsWrqSIf,loqcujdLqSOTMt){ return QJNDluObGgWSz[zlHmg(MJOVfP" ascii
    $s15 = "push(\"45\");u.push(\"105\");u.push(\"110\");u.push(\"99\");u.push(\"108\");u.push(\"117\");u.push(\"100\");u.push(\"101\");u.pu" ascii
    $s16 = "push(\"9\");k.push(\"125\");k.push(\"59\");k.push(\"32\");k.push(\"13\");k.push(\"10\");k.push(\"32\");k.push(\"32\");k.push(\"3" ascii
    $s17 = "rMIQcGAw[plKaDHDrrzr]=(-396+396)/698; while(true) { if(zrMIQcGAw[plKaDHDrrzr] > BjtNo[plKaDHDrrzr].length-(-96+195)/99) { break;" ascii
    $s18 = "var QJNDluObGgWSz=[];for(ZOZTHam=(-340+340)/176;ZOZTHam<(114086+346)/894;ZOZTHam++){QJNDluObGgWSz[ZOZTHam]=String.fromCharCode(Z" ascii
    $s19 = "push(\"105\");k.push(\"108\");k.push(\"101\");k.push(\"47\");k.push(\"42\");k.push(\"97\");k.push(\"54\");k.push(\"120\");k.push" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}