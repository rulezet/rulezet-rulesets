rule sig_20151210_bc9f03923398b6a7ab184e732e5b8e93 {
  meta:
    description = "datamaliciousorder - file 20151210_bc9f03923398b6a7ab184e732e5b8e93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2836790c14114907d5eb61a34c419683c4db65d332a5ef325fff6ac895ab560"

  strings:
    $s1  = "function lFUriot(azXFKWepEjgZDpbqSSTwkLovBDRpXxNWtelt) {return !isNaN(parseFloat(azXFKWepEjgZDpbqSSTwkLovBDRpXxNWtelt)) && isFin" ascii
    $s2  = "function lFUriot(azXFKWepEjgZDpbqSSTwkLovBDRpXxNWtelt) {return !isNaN(parseFloat(azXFKWepEjgZDpbqSSTwkLovBDRpXxNWtelt)) && isFin" ascii
    $s3  = "eZMHuwNW[JMlgVfsxfWi]=(-641+641)/265; while(true) { if(IeZMHuwNW[JMlgVfsxfWi] > VYbbN[JMlgVfsxfWi].length-(-580+736)/156) { brea" ascii
    $s4  = "function jGcyl(fqZTarKqXmR,WTkMnpoiKXrgR,OJWewNwj){YsWc=parseInt(fqZTarKqXmR,WTkMnpoiKXrgR);WZepy=YsWc.toString(OJWewNwj);return" ascii
    $s5  = "djbuiXT=(-821+821)/77;while(true){if(djbuiXT>=(113183+993)/892){break;}OdbdQZETZhivs[djbuiXT]=String.fromCharCode(djbuiXT);djbui" ascii
    $s6  = "function jGcyl(fqZTarKqXmR,WTkMnpoiKXrgR,OJWewNwj){YsWc=parseInt(fqZTarKqXmR,WTkMnpoiKXrgR);WZepy=YsWc.toString(OJWewNwj);return" ascii
    $s7  = "+;}} return tlflwtYVGRE}" fullword ascii
    $s8  = "function aZPzuxOHLvNhMbYaW(VYbbN){tlflwtYVGRE= '';for(JMlgVfsxfWi=(-720+720)/291; JMlgVfsxfWi < (443+585)/514; JMlgVfsxfWi++) {I" ascii
    $s9  = "function aQkmfmCLccpGzXsFAWPCjxtmIKrXooaZfNmwLUQIpyeMZpYaLkLGPh(VUpkmvBRRqsDC,PsTNgeacLiLVWH){ return OdbdQZETZhivs[jGcyl(VUpkmv" ascii
    $s10 = "function aQkmfmCLccpGzXsFAWPCjxtmIKrXooaZfNmwLUQIpyeMZpYaLkLGPh(VUpkmvBRRqsDC,PsTNgeacLiLVWH){ return OdbdQZETZhivs[jGcyl(VUpkmv" ascii
    $s11 = "function aZPzuxOHLvNhMbYaW(VYbbN){tlflwtYVGRE= '';for(JMlgVfsxfWi=(-720+720)/291; JMlgVfsxfWi < (443+585)/514; JMlgVfsxfWi++) {I" ascii
    $s12 = " WZepy;}function FXLfexHDeMibdKt(JvAzmmAGDkqPqVOOz){eval(JvAzmmAGDkqPqVOOz)}" fullword ascii
    $s13 = "djbuiXT=(-821+821)/77;while(true){if(djbuiXT>=(113183+993)/892){break;}OdbdQZETZhivs[djbuiXT]=String.fromCharCode(djbuiXT);djbui" ascii
    $s14 = "function ztcEPuaCMXL(jogMlhsr,eWXUwV){return jogMlhsr.split(eWXUwV)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}