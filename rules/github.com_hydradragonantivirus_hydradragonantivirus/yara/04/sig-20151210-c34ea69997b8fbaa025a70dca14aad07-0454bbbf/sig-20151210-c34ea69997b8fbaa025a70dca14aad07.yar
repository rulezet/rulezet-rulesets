rule sig_20151210_c34ea69997b8fbaa025a70dca14aad07 {
  meta:
    description = "datamaliciousorder - file 20151210_c34ea69997b8fbaa025a70dca14aad07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13795e7a295cb6099fbcf43bfc8fab89ed88ee1f76d5fdbe32718a4048327c4c"

  strings:
    $s1  = "function kBiwowH(huDaNucrkKntLYrsehoSvYuyyulIxKLqkeMc) {return !isNaN(parseFloat(huDaNucrkKntLYrsehoSvYuyyulIxKLqkeMc)) && isFin" ascii
    $s2  = "function kBiwowH(huDaNucrkKntLYrsehoSvYuyyulIxKLqkeMc) {return !isNaN(parseFloat(huDaNucrkKntLYrsehoSvYuyyulIxKLqkeMc)) && isFin" ascii
    $s3  = "function cWyePKVNDVZTwYXWklGjDVoHDLflCboKTkqfHqgqkknMCRVdGgpxLo(mynqUOGsKjxBX,QDVDVMhRhzpLxo){ return jrZMhoVZQIxKY[lDfIk(mynqUO" ascii
    $s4  = "function cWyePKVNDVZTwYXWklGjDVoHDLflCboKTkqfHqgqkknMCRVdGgpxLo(mynqUOGsKjxBX,QDVDVMhRhzpLxo){ return jrZMhoVZQIxKY[lDfIk(mynqUO" ascii
    $s5  = "function scWTgsNGlTeGxSrOW(CZUMe){nEoJBFImycn= '';for(OckYslGGxuu=(-894+894)/473; OckYslGGxuu < (-27+611)/292; OckYslGGxuu++) {G" ascii
    $s6  = "function scWTgsNGlTeGxSrOW(CZUMe){nEoJBFImycn= '';for(OckYslGGxuu=(-894+894)/473; OckYslGGxuu < (-27+611)/292; OckYslGGxuu++) {G" ascii
    $s7  = "RXgMqxTR[OckYslGGxuu]=(-864+864)/713; while(true) { if(GRXgMqxTR[OckYslGGxuu] > CZUMe[OckYslGGxuu].length-(-871+920)/49) { break" ascii
    $s8  = "fillJvY=(-538+538)/815;while(true){if(fillJvY>=(23987+205)/189){break;}jrZMhoVZQIxKY[fillJvY]=String.fromCharCode(fillJvY);fillJ" ascii
    $s9  = "function lDfIk(uetKnzBqfow,SHxAQpkrFGQxD,RwsthVhv){cXAD=parseInt(uetKnzBqfow,SHxAQpkrFGQxD);apQlE=cXAD.toString(RwsthVhv);return" ascii
    $s10 = "function lDfIk(uetKnzBqfow,SHxAQpkrFGQxD,RwsthVhv){cXAD=parseInt(uetKnzBqfow,SHxAQpkrFGQxD);apQlE=cXAD.toString(RwsthVhv);return" ascii
    $s11 = "fillJvY=(-538+538)/815;while(true){if(fillJvY>=(23987+205)/189){break;}jrZMhoVZQIxKY[fillJvY]=String.fromCharCode(fillJvY);fillJ" ascii
    $s12 = " apQlE;}function kmkIHMqNIKxghUo(PZKHsBnvCtImFMRsU){eval(PZKHsBnvCtImFMRsU)}" fullword ascii
    $s13 = "++;}} return nEoJBFImycn}" fullword ascii
    $s14 = "function zwMKxttOkBZ(UCiurcau,IiPrAg){return UCiurcau.split(IiPrAg)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}