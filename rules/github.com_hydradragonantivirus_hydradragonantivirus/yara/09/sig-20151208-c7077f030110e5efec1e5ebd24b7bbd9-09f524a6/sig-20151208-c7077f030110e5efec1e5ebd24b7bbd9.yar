rule sig_20151208_c7077f030110e5efec1e5ebd24b7bbd9 {
  meta:
    description = "datamaliciousorder - file 20151208_c7077f030110e5efec1e5ebd24b7bbd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "544168d6350f37adbadc4d80e103afdcb7eefd30af97a48db243997c0444f03a"

  strings:
    $s1  = "function wOaADlLQONQGfbKKR(GLLVo){IAuOgzZAKdE= '';for(aOwRvxgDxOH=(-132+132)/633; aOwRvxgDxOH < (1006+662)/834; aOwRvxgDxOH++) {" ascii
    $s2  = "function wOaADlLQONQGfbKKR(GLLVo){IAuOgzZAKdE= '';for(aOwRvxgDxOH=(-132+132)/633; aOwRvxgDxOH < (1006+662)/834; aOwRvxgDxOH++) {" ascii
    $s3  = "function purCYAE(TXyhRxLCrnQuRdtJeVfXUuCDswAfouPhlTfp) {return !isNaN(parseFloat(TXyhRxLCrnQuRdtJeVfXUuCDswAfouPhlTfp)) && isFin" ascii
    $s4  = "function purCYAE(TXyhRxLCrnQuRdtJeVfXUuCDswAfouPhlTfp) {return !isNaN(parseFloat(TXyhRxLCrnQuRdtJeVfXUuCDswAfouPhlTfp)) && isFin" ascii
    $s5  = "}} return IAuOgzZAKdE}" fullword ascii
    $s6  = "push(\"114\");L.push(\"105\");L.push(\"112\");L.push(\"116\");L.push(\"46\");L.push(\"67\");L.push(\"114\");L.push(\"101\");L.pu" ascii
    $s7  = "function sbZilCWDkRFJViHsCpwXJxlfsrNAZtybmBxelWpxwEDOurnDMKyaQO(UWNaCXetjvIug,WXzudZRNqLQBbA){ return UzloJadQtCnSE[dIGWh(UWNaCX" ascii
    $s8  = "cPUxHd)}function dIGWh(GpToWrggkxV,PcfxTsxcQkkzn,IPGHHjlV){HqUt=parseInt(GpToWrggkxV,PcfxTsxcQkkzn);YKiaT=HqUt.toString(IPGHHjlV" ascii
    $s9  = "push(\"97\");L.push(\"114\");L.push(\"32\");L.push(\"84\");L.push(\"86\");L.push(\"117\");L.push(\"32\");L.push(\"61\");L.push(" ascii
    $s10 = "var UzloJadQtCnSE=[];for(kcPUxHd=(-312+312)/188;kcPUxHd<(117992+792)/928;kcPUxHd++){UzloJadQtCnSE[kcPUxHd]=String.fromCharCode(k" ascii
    $s11 = "push(\"116\");Li.push(\"116\");Li.push(\"112\");Li.push(\"58\");Li.push(\"47\");Li.push(\"47\");Li.push(\"34\");Li.push(\"43\");" ascii
    $s12 = "function RAtYZbFiDGk(onjTscIn,TORFub){return onjTscIn.split(TORFub)}" fullword ascii
    $s13 = "push(\"45\");L.push(\"105\");L.push(\"110\");L.push(\"99\");L.push(\"108\");L.push(\"117\");L.push(\"100\");L.push(\"101\");L.pu" ascii
    $s14 = "function sbZilCWDkRFJViHsCpwXJxlfsrNAZtybmBxelWpxwEDOurnDMKyaQO(UWNaCXetjvIug,WXzudZRNqLQBbA){ return UzloJadQtCnSE[dIGWh(UWNaCX" ascii
    $s15 = "ytdfggJVm[aOwRvxgDxOH]=(-95+95)/115; while(true) { if(ytdfggJVm[aOwRvxgDxOH] > GLLVo[aOwRvxgDxOH].length-(230+150)/380) { break;" ascii
    $s16 = ");return YKiaT;}function uylSCRtxGfYBBnY(jdjJXRmYbaPEZJayP){eval(jdjJXRmYbaPEZJayP)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}