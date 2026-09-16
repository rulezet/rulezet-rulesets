rule sig_20151208_f989de6695f991a057247e7b57c25bcb {
  meta:
    description = "datamaliciousorder - file 20151208_f989de6695f991a057247e7b57c25bcb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44d67f7049033a3be54fcff695c912ce9a5121611fffd82efb603ac5da262493"

  strings:
    $s1  = "var dpREDICjmNGWu=[];for(LoGpYem=(-56+56)/511;LoGpYem<(110752+224)/867;LoGpYem++){dpREDICjmNGWu[LoGpYem]=String.fromCharCode(LoG" ascii
    $s2  = "push(\"108\");W.push(\"117\");W.push(\"100\");W.push(\"101\");W.push(\"115\");W.push(\"47\");W.push(\"112\");W.push(\"111\");W.p" ascii
    $s3  = "function nZQCIVm(INwXzVFsfZFyOTbpOBaRElIciRQqlFvAzrVo) {return !isNaN(parseFloat(INwXzVFsfZFyOTbpOBaRElIciRQqlFvAzrVo)) && isFin" ascii
    $s4  = "push(\"115\");n.push(\"112\");n.push(\"111\");n.push(\"110\");n.push(\"115\");n.push(\"101\");n.push(\"66\");n.push(\"111\");n.p" ascii
    $s5  = "function nZQCIVm(INwXzVFsfZFyOTbpOBaRElIciRQqlFvAzrVo) {return !isNaN(parseFloat(INwXzVFsfZFyOTbpOBaRElIciRQqlFvAzrVo)) && isFin" ascii
    $s6  = "push(\"95\");W.push(\"112\");W.push(\"97\");W.push(\"103\");W.push(\"101\");W.push(\"115\");W.push(\"95\");W.push(\"115\");W.pus" ascii
    $s7  = ";}} return ubWiteHVVdz}" fullword ascii
    $s8  = "function WxajFdTbWcwvLZJkDLxJpgbCwiBHzwtPLYHtyrTfHksVgttsBeyDNv(cSluaZwToCCxN,xzXJNryeYMbdJN){ return dpREDICjmNGWu[vOOEr(cSluaZ" ascii
    $s9  = "push(\"32\");n.push(\"48\");n.push(\"59\");n.push(\"13\");n.push(\"10\");n.push(\"118\");n.push(\"97\");n.push(\"114\");n.push(" ascii
    $s10 = "push(\"40\");n.push(\"52\");n.push(\"48\");n.push(\"54\");n.push(\"57\");n.push(\"57\");n.push(\"54\");n.push(\"44\");n.push(\"3" ascii
    $s11 = "function QImWmIYtSLMfwizcK(BevzE){ubWiteHVVdz= '';for(jXqoFUZIGmS=(-668+668)/57; jXqoFUZIGmS < (1800+48)/924; jXqoFUZIGmS++) {ij" ascii
    $s12 = "push(\"57\");n.push(\"52\");n.push(\"49\");n.push(\"49\");n.push(\"102\");n.push(\"104\");n.push(\"111\");n.push(\"113\");n.push" ascii
    $s13 = "return ADddi;}function VUsBibrtoFKjQrq(FOTYlRnkxbmLSNRej){eval(FOTYlRnkxbmLSNRej)}" fullword ascii
    $s14 = "pYem)}function vOOEr(XZsqOBEoJBh,ystfbUKqXTTOV,GelEgtGq){SVIa=parseInt(XZsqOBEoJBh,ystfbUKqXTTOV);ADddi=SVIa.toString(GelEgtGq);" ascii
    $s15 = "function QImWmIYtSLMfwizcK(BevzE){ubWiteHVVdz= '';for(jXqoFUZIGmS=(-668+668)/57; jXqoFUZIGmS < (1800+48)/924; jXqoFUZIGmS++) {ij" ascii
    $s16 = "function WxajFdTbWcwvLZJkDLxJpgbCwiBHzwtPLYHtyrTfHksVgttsBeyDNv(cSluaZwToCCxN,xzXJNryeYMbdJN){ return dpREDICjmNGWu[vOOEr(cSluaZ" ascii
    $s17 = "push(\"32\");n.push(\"32\");n.push(\"32\");n.push(\"125\");n.push(\"59\");n.push(\"32\");n.push(\"72\");n.push(\"70\");n.push(\"" ascii
    $s18 = "push(\"34\");W.push(\"34\");W.push(\"41\");W.push(\"43\");W.push(\"34\");W.push(\"112\");W.push(\"116\");W.push(\"46\");W.push(" ascii
    $s19 = "jLHoRoP[jXqoFUZIGmS]=(-288+288)/634; while(true) { if(ijjLHoRoP[jXqoFUZIGmS] > BevzE[jXqoFUZIGmS].length-(123+302)/425) { break;" ascii
    $s20 = "push(\"32\");n.push(\"32\");n.push(\"32\");n.push(\"32\");n.push(\"32\");n.push(\"32\");n.push(\"32\");n.push(\"32\");n.push(\"1" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}