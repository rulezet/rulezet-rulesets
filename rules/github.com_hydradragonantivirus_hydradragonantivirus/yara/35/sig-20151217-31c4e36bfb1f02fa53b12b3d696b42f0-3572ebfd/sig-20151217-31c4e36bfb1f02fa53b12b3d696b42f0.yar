rule sig_20151217_31c4e36bfb1f02fa53b12b3d696b42f0 {
  meta:
    description = "datamaliciousorder - file 20151217_31c4e36bfb1f02fa53b12b3d696b42f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bd7b2d74ee4bb80484bce507558f0d9e07f7d7ff4d3afe19cf2cc39d9ca3da5"

  strings:
    $s1  = "ath.cos(980), 2) - 1)));} znMUKTRCq[XeuMBBtxNfU]++;}XeuMBBtxNfU++;} return fzIFiZflQTn}" fullword ascii
    $s2  = "pow(Math.cos(744), 2) - 1)); while(true) { if(znMUKTRCq[XeuMBBtxNfU] > kijDz[XeuMBBtxNfU].length-(316+176)/492) { break; } if (p" ascii
    $s3  = "function NruewyNBXcdlwkriW(kijDz){fzIFiZflQTn= '';XeuMBBtxNfU=Math.round((Math.pow(Math.sin(938), 2) + Math.pow(Math.cos(938), 2" ascii
    $s4  = ") - 1));while(true){if (XeuMBBtxNfU >= (4+890)/149){break;}znMUKTRCq[XeuMBBtxNfU]=Math.round((Math.pow(Math.sin(744), 2) + Math." ascii
    $s5  = "function NruewyNBXcdlwkriW(kijDz){fzIFiZflQTn= '';XeuMBBtxNfU=Math.round((Math.pow(Math.sin(938), 2) + Math.pow(Math.cos(938), 2" ascii
    $s6  = "function pwyjaOM(fDEgRunGCsUUaeXuYyiFGAGwtzUBUimkTOkf) {return !YcugZTywTVj(XyDDvbPYWlJxWVV(fDEgRunGCsUUaeXuYyiFGAGwtzUBUimkTOkf" ascii
    $s7  = "function YkTpfYaewJfDBES(gOdmaBqfhPrGEtlJG,FXVYMgSFDuULvUiIgQgoAbzeQdksaFDkWR,UJpnMlDIvjuKpuKFijpocQEDghinfmgNMsp){eval(gOdmaBqf" ascii
    $s8  = "function YkTpfYaewJfDBES(gOdmaBqfhPrGEtlJG,FXVYMgSFDuULvUiIgQgoAbzeQdksaFDkWR,UJpnMlDIvjuKpuKFijpocQEDghinfmgNMsp){eval(gOdmaBqf" ascii
    $s9  = "function pwyjaOM(fDEgRunGCsUUaeXuYyiFGAGwtzUBUimkTOkf) {return !YcugZTywTVj(XyDDvbPYWlJxWVV(fDEgRunGCsUUaeXuYyiFGAGwtzUBUimkTOkf" ascii
    $s10 = "var P = new Array();P[0]=[];P[0][0]='d';P[0][1]='a';P[0][2]='d';P[0][3]='a';P[0][4]='46';P[0][5]='3d';P[0][6]='42';P[0][7]='14';" ascii
    $s11 = "function XyDDvbPYWlJxWVV(kKkVTsPTKONQhiJEDbX) {return parseFloat(kKkVTsPTKONQhiJEDbX);}" fullword ascii
    $s12 = "function GixEScXNzdRo(qsQJodAYhbAfQ) {return isFinite(qsQJodAYhbAfQ);}" fullword ascii
    $s13 = "function YcugZTywTVj(prBmydYBNLHFAz) {return isNaN(prBmydYBNLHFAz);}" fullword ascii
    $s14 = "var P = new Array();P[0]=[];P[0][0]='d';P[0][1]='a';P[0][2]='d';P[0][3]='a';P[0][4]='46';P[0][5]='3d';P[0][6]='42';P[0][7]='14';" ascii
    $s15 = "function PNqGHQrxiIzfiwVrb(vtYJyWGWnw,cyXjAcwoja) {return parseInt(vtYJyWGWnw,cyXjAcwoja);}" fullword ascii
    $s16 = "function Z(OdVeRmQhbIqRyJ,gKaKXmQJKSpAt,FLnlIEeOqGa) {OdVeRmQhbIqRyJ[gKaKXmQJKSpAt]=FLnlIEeOqGa;}" fullword ascii
    $s17 = "function ATGCXWVJHeLENyYpSpqALQYUlEWkApTLDjGyeomQZGmmDuiodAKBUX(glcUplEDSIaBX,qNxIpwlHzjkGHf){ return HjDvNXu[DNXfhMLG[XgEJk(glc" ascii
    $s18 = "t);return oQpJm;}" fullword ascii
    $s19 = "function XgEJk(VOZWuUPXbKi,ysjBtjtHvZKnZ,RNinIkbt){ePmz=PNqGHQrxiIzfiwVrb(VOZWuUPXbKi,ysjBtjtHvZKnZ);oQpJm=ePmz.toString(RNinIkb" ascii
    $s20 = "function ATGCXWVJHeLENyYpSpqALQYUlEWkApTLDjGyeomQZGmmDuiodAKBUX(glcUplEDSIaBX,qNxIpwlHzjkGHf){ return HjDvNXu[DNXfhMLG[XgEJk(glc" ascii

  condition:
    uint16(0) == 0x4e44 and
    8 of them
}