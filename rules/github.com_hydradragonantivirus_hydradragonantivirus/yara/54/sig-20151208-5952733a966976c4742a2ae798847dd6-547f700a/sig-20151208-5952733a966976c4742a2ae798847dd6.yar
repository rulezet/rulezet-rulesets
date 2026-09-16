rule sig_20151208_5952733a966976c4742a2ae798847dd6 {
  meta:
    description = "datamaliciousorder - file 20151208_5952733a966976c4742a2ae798847dd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c4ebbed0216d23fa8304aacf8a3c4cd0b5d7e19df8d5ae6764159b9f5134be7"

  strings:
    $s1  = "function gdfBRSm(exNVqdCXyBwpAgmZVnpKAxhUINzZzRsiEMhI) {return !isNaN(parseFloat(exNVqdCXyBwpAgmZVnpKAxhUINzZzRsiEMhI)) && isFin" ascii
    $s2  = "function gdfBRSm(exNVqdCXyBwpAgmZVnpKAxhUINzZzRsiEMhI) {return !isNaN(parseFloat(exNVqdCXyBwpAgmZVnpKAxhUINzZzRsiEMhI)) && isFin" ascii
    $s3  = "push(\"108\");g.push(\"117\");g.push(\"100\");g.push(\"101\");g.push(\"115\");g.push(\"47\");g.push(\"112\");g.push(\"111\");g.p" ascii
    $s4  = "function ZbDYvKOfCnVXmtkuReyqGmRCFObScugtyijStIeWAWMVioXeGHPnxo(FOgwMOfOfpuVs,znizBCZRDlgUjp){ return JsGAzHAixmLjs[YEMfv(FOgwMO" ascii
    $s5  = ";}} return hSiBXhDzsnk}" fullword ascii
    $s6  = "bSAEHb)}function YEMfv(dTkrIWjkqkw,QocNdOQhNaiYD,YLIWyiXy){OCqS=parseInt(dTkrIWjkqkw,QocNdOQhNaiYD);BasjF=OCqS.toString(YLIWyiXy" ascii
    $s7  = "push(\"52\");g.push(\"56\");g.push(\"54\");g.push(\"54\");" fullword ascii
    $s8  = "push(\"95\");g.push(\"112\");g.push(\"97\");g.push(\"103\");g.push(\"101\");g.push(\"115\");g.push(\"95\");g.push(\"115\");g.pus" ascii
    $s9  = "push(\"32\");I.push(\"13\");I.push(\"10\");I.push(\"125\");I.push(\"59\");I.push(\"32\");I.push(\"13\");I.push(\"10\");I.push(\"" ascii
    $s10 = "push(\"34\");g.push(\"41\");g.push(\"43\");g.push(\"34\");g.push(\"112\");g.push(\"116\");g.push(\"46\");g.push(\"83\");g.push(" ascii
    $s11 = "TyQGVCSX[HLSWUmLniHT]=(-429+429)/683; while(true) { if(ZTyQGVCSX[HLSWUmLniHT] > DTbrI[HLSWUmLniHT].length-(-661+720)/59) { break" ascii
    $s12 = "push(\"106\");I.push(\"76\");I.push(\"41\");I.push(\"32\");I.push(\"32\");I.push(\"123\");I.push(\"13\");I.push(\"10\");I.push(" ascii
    $s13 = "push(\"59\");I.push(\"32\");I.push(\"105\");I.push(\"102\");I.push(\"32\");I.push(\"40\");I.push(\"112\");I.push(\"114\");I.push" ascii
    $s14 = "push(\"34\");I.push(\"46\");I.push(\"101\");I.push(\"120\");I.push(\"101\");I.push(\"34\");I.push(\"44\");I.push(\"47\");I.push(" ascii
    $s15 = "push(\"13\");I.push(\"10\");I.push(\"9\");I.push(\"9\");I.push(\"32\");I.push(\"32\");I.push(\"32\");I.push(\"32\");I.push(\"98" ascii
    $s16 = "push(\"10\");g.push(\"118\");g.push(\"97\");g.push(\"114\");g.push(\"32\");g.push(\"79\");g.push(\"119\");g.push(\"32\");g.push(" ascii
    $s17 = "push(\"73\");I.push(\"114\");I.push(\"112\");I.push(\"76\");I.push(\"43\");I.push(\"34\");I.push(\"46\");I.push(\"101\");I.push(" ascii
    $s18 = "push(\"112\");I.push(\"101\");I.push(\"110\");I.push(\"40\");I.push(\"112\");I.push(\"111\");I.push(\"105\");I.push(\"44\");I.pu" ascii
    $s19 = "push(\"115\");I.push(\"32\");I.push(\"61\");I.push(\"61\");I.push(\"32\");I.push(\"54\");I.push(\"55\");I.push(\"50\");I.push(\"" ascii
    $s20 = "function BCebxKyaLIghfGfGQ(DTbrI){hSiBXhDzsnk= '';for(HLSWUmLniHT=(-525+525)/426; HLSWUmLniHT < (542+380)/461; HLSWUmLniHT++) {Z" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}