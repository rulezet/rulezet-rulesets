rule sig_20151211_c1c6fe51376796988317c8b101bd3eb8 {
  meta:
    description = "datamaliciousorder - file 20151211_c1c6fe51376796988317c8b101bd3eb8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa1f55594731f3d36171259d52c9af54a88ede355579e8fc1e627515bc549319"

  strings:
    $s1  = "var e=new Array(\"2e\",\"2a\",\"2a\",\"29\",\"2d\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s2  = "function UVCwQ(VSAOClcMSbE,KTnKjuMycRTRX,XvrqYvrL){SaQd=parseInt(VSAOClcMSbE,KTnKjuMycRTRX);cyJtr=SaQd.toString(XvrqYvrL);return" ascii
    $s3  = "function VfHSrvgzcibHACGSTUqgxORtQGsRVXfrNorxkTiOuCwbyvRFsCSwGn(VpiFrqzSmFPlZ,fEcXcorTSUjGyI){ return uxFml[UVCwQ(VpiFrqzSmFPlZ[" ascii
    $s4  = "function jaBaFHAkIqC(RefIQPVv,TuogXL){return RefIQPVv.split(TuogXL)}" fullword ascii
    $s5  = " cyJtr;}function UGjDtxAOniAKQmi(JDVJjLwcVJomJyxce){eval(JDVJjLwcVJomJyxce)}" fullword ascii
    $s6  = "var Z=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5g\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = "function dHZqnOMrYVESnhdiY(bDQOl){WkZsNOwUVDS= '';AooHSlhhTTd=(-151+151)/620; while(true){if(AooHSlhhTTd >= (929+181)/555)break;" ascii
    $s8  = "function VfHSrvgzcibHACGSTUqgxORtQGsRVXfrNorxkTiOuCwbyvRFsCSwGn(VpiFrqzSmFPlZ,fEcXcorTSUjGyI){ return uxFml[UVCwQ(VpiFrqzSmFPlZ[" ascii
    $s9  = "var e=new Array(\"2e\",\"2a\",\"2a\",\"29\",\"2d\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s10 = "d]++;}AooHSlhhTTd++;} return WkZsNOwUVDS}" fullword ascii
    $s11 = "function UVCwQ(VSAOClcMSbE,KTnKjuMycRTRX,XvrqYvrL){SaQd=parseInt(VSAOClcMSbE,KTnKjuMycRTRX);cyJtr=SaQd.toString(XvrqYvrL);return" ascii
    $s12 = "uztZjTjTF[AooHSlhhTTd]=(-211+211)/859; while(true) { if(uztZjTjTF[AooHSlhhTTd] > bDQOl[AooHSlhhTTd].length-(-626+804)/178) { bre" ascii
    $s13 = "var Z=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5g\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s14 = "function PMpcaEv(wHhLkQQZgEHvVMNJPKLVvPnbCfaTcbGUKAok) {return !isNaN(parseFloat(wHhLkQQZgEHvVMNJPKLVvPnbCfaTcbGUKAok)) && isFin" ascii
    $s15 = "function PMpcaEv(wHhLkQQZgEHvVMNJPKLVvPnbCfaTcbGUKAok) {return !isNaN(parseFloat(wHhLkQQZgEHvVMNJPKLVvPnbCfaTcbGUKAok)) && isFin" ascii
    $s16 = "function dHZqnOMrYVESnhdiY(bDQOl){WkZsNOwUVDS= '';AooHSlhhTTd=(-151+151)/620; while(true){if(AooHSlhhTTd >= (929+181)/555)break;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}