rule sig_20151216_9c04623673fbfc869e3019b047e59048 {
  meta:
    description = "datamaliciousorder - file 20151216_9c04623673fbfc869e3019b047e59048.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3a6ea1c1b56280cb1ce21bdf07c462233a94f95e4296641b5bca52f0256faf5"

  strings:
    $s1  = "function FRdbkaWYjoXRiSpiX(jinFV){PVyTxNYRxBy= '';wauCSFmPCUX=Math.round((Math.pow(Math.sin(11), 2) + Math.pow(Math.cos(11), 2) " ascii
    $s2  = "w(Math.cos(363), 2) - 1)));} mvbhLrmPb[wauCSFmPCUX]++;}wauCSFmPCUX++;} return PVyTxNYRxBy}" fullword ascii
    $s3  = ".pow(Math.cos(821), 2) - 1)); while(true) { if(mvbhLrmPb[wauCSFmPCUX] > jinFV[wauCSFmPCUX].length-(-40+837)/797) { break; } if (" ascii
    $s4  = "function FRdbkaWYjoXRiSpiX(jinFV){PVyTxNYRxBy= '';wauCSFmPCUX=Math.round((Math.pow(Math.sin(11), 2) + Math.pow(Math.cos(11), 2) " ascii
    $s5  = "- 1));while(true){if (wauCSFmPCUX >= (1443+801)/374){break;}mvbhLrmPb[wauCSFmPCUX]=Math.round((Math.pow(Math.sin(821), 2) + Math" ascii
    $s6  = "function kYOXyVy(ZoSBuuzkECFPrQwqlIDbJOCtOYAPFsRIGjsd) {return !CqsAKxKGihB(XFMkbXjgElFpaXg(ZoSBuuzkECFPrQwqlIDbJOCtOYAPFsRIGjsd" ascii
    $s7  = "function QAfgbRGDCBPapbmJP(zpuYjQpdCv,QGoCDvaxtd) {return parseInt(zpuYjQpdCv,QGoCDvaxtd);}" fullword ascii
    $s8  = "function FZhkagggtNWOToHLSjdvnGOjZggmBxJMzetccJbAmMUXgUpWeJoDKt(DCxthkRAZyKSA,uSYhSBKzqAOcVF){ return PPWrNVV[GCYIrwJz[iCnBN(DCx" ascii
    $s9  = "o);return eYnYq;}" fullword ascii
    $s10 = "function elInJwraBAcQMHl(dSbWcZwYLJkLAUyfq,QmgSexiqEyVXSxibLJTTnLJpaBZEaJnPhT,FDjgNzdqDSyvRWRnRVQzCpqCtRdlRRptUZX){eval(dSbWcZwY" ascii
    $s11 = "function kYOXyVy(ZoSBuuzkECFPrQwqlIDbJOCtOYAPFsRIGjsd) {return !CqsAKxKGihB(XFMkbXjgElFpaXg(ZoSBuuzkECFPrQwqlIDbJOCtOYAPFsRIGjsd" ascii
    $s12 = "function p(VinUotODqPKyjI,UetkdSTEfncIJ,jATtlSNYAdn) {VinUotODqPKyjI[UetkdSTEfncIJ]=jATtlSNYAdn;}" fullword ascii
    $s13 = "function elInJwraBAcQMHl(dSbWcZwYLJkLAUyfq,QmgSexiqEyVXSxibLJTTnLJpaBZEaJnPhT,FDjgNzdqDSyvRWRnRVQzCpqCtRdlRRptUZX){eval(dSbWcZwY" ascii
    $s14 = "function XFMkbXjgElFpaXg(QtIUUbCuFhifmQXPSBe) {return parseFloat(QtIUUbCuFhifmQXPSBe);}" fullword ascii
    $s15 = "var G = new Array();G[0]=[];G[0][0]='d';G[0][1]='a';G[0][2]='d';G[0][3]='a';G[0][4]='46';G[0][5]='3d';G[0][6]='42';G[0][7]='14';" ascii
    $s16 = "function CqsAKxKGihB(eVkSHoOHCCDIXr) {return isNaN(eVkSHoOHCCDIXr);}" fullword ascii
    $s17 = "var G = new Array();G[0]=[];G[0][0]='d';G[0][1]='a';G[0][2]='d';G[0][3]='a';G[0][4]='46';G[0][5]='3d';G[0][6]='42';G[0][7]='14';" ascii
    $s18 = "function SJYTyGqTKFgD(ZEahANmQeZshG) {return isFinite(ZEahANmQeZshG);}" fullword ascii
    $s19 = "function FZhkagggtNWOToHLSjdvnGOjZggmBxJMzetccJbAmMUXgUpWeJoDKt(DCxthkRAZyKSA,uSYhSBKzqAOcVF){ return PPWrNVV[GCYIrwJz[iCnBN(DCx" ascii
    $s20 = "function t(ewwJzJEWSBab,CksnFhXueOaqXI){ewwJzJEWSBab.push(CksnFhXueOaqXI);}" fullword ascii

  condition:
    uint16(0) == 0x4347 and
    8 of them
}