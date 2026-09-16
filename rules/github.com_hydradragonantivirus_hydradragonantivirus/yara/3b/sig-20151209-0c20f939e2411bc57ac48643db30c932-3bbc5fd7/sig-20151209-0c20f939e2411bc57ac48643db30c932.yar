rule sig_20151209_0c20f939e2411bc57ac48643db30c932 {
  meta:
    description = "datamaliciousorder - file 20151209_0c20f939e2411bc57ac48643db30c932.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2481ce7e901d303622b4c19e60b128a82bfd933fc444b84e06c9b7f6d81db3e"

  strings:
    $s1  = "function pHvGaIc(GdNJDuVJFoWAFFIeUWMZYrypIgfEYbGeUnvC) {return !isNaN(parseFloat(GdNJDuVJFoWAFFIeUWMZYrypIgfEYbGeUnvC)) && isFin" ascii
    $s2  = "function pHvGaIc(GdNJDuVJFoWAFFIeUWMZYrypIgfEYbGeUnvC) {return !isNaN(parseFloat(GdNJDuVJFoWAFFIeUWMZYrypIgfEYbGeUnvC)) && isFin" ascii
    $s3  = "function bRlYS(gXQEJwDDDxd,cllURPjSTYlRt,roYIPwiv){nVJy=parseInt(gXQEJwDDDxd,cllURPjSTYlRt);SZlTS=nVJy.toString(roYIPwiv);return" ascii
    $s4  = " SZlTS;}function TfuriKPFdTlmbdV(cgNvPctwPwYrdYYgS){eval(cgNvPctwPwYrdYYgS)}" fullword ascii
    $s5  = "function gkYyaOgOLhjjzgSZEbcJzVGqNZoDwqsgDxzhcZksHoeatvEEUaQTCL(BirjglEcVYynj,PzHZRcheOrWHxD){ return CwDuU[bRlYS(BirjglEcVYynj[" ascii
    $s6  = "nifXEzAJG[cFhbMGKTUVQ]=(-551+551)/710; while(true) { if(nifXEzAJG[cFhbMGKTUVQ] > Xrpim[cFhbMGKTUVQ].length-(-91+776)/685) { brea" ascii
    $s7  = "function PpvhFWySNMKrnDCEJ(Xrpim){BAbWAndcLmz= '';for(cFhbMGKTUVQ=(-665+665)/787; cFhbMGKTUVQ < (-668+890)/111; cFhbMGKTUVQ++) {" ascii
    $s8  = "function ezcdtWbbuQj(qRTsEqIZ,wQKlga){return qRTsEqIZ.split(wQKlga)}" fullword ascii
    $s9  = "function gkYyaOgOLhjjzgSZEbcJzVGqNZoDwqsgDxzhcZksHoeatvEEUaQTCL(BirjglEcVYynj,PzHZRcheOrWHxD){ return CwDuU[bRlYS(BirjglEcVYynj[" ascii
    $s10 = "function bRlYS(gXQEJwDDDxd,cllURPjSTYlRt,roYIPwiv){nVJy=parseInt(gXQEJwDDDxd,cllURPjSTYlRt);SZlTS=nVJy.toString(roYIPwiv);return" ascii
    $s11 = ";}} return BAbWAndcLmz}" fullword ascii
    $s12 = "function PpvhFWySNMKrnDCEJ(Xrpim){BAbWAndcLmz= '';for(cFhbMGKTUVQ=(-665+665)/787; cFhbMGKTUVQ < (-668+890)/111; cFhbMGKTUVQ++) {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}