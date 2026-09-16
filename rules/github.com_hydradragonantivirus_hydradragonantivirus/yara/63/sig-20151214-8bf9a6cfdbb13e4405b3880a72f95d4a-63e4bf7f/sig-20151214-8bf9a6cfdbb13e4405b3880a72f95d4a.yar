rule sig_20151214_8bf9a6cfdbb13e4405b3880a72f95d4a {
  meta:
    description = "datamaliciousorder - file 20151214_8bf9a6cfdbb13e4405b3880a72f95d4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "877902305e5df8caff69314d16babd7dd54507c6ddaf26c106ae2ee02d34e747"

  strings:
    $s1  = "Math.pow(Math.cos(331), 2) - 1)); while(true) { if(fQQJVFtsY[iqtSkuMFQNj] > KAbLN[iqtSkuMFQNj].length-(-213+370)/157) { break; }" ascii
    $s2  = "h.pow(Math.cos(87), 2) - 1)));} fQQJVFtsY[iqtSkuMFQNj]++;}} return VUsANXOGYsL}" fullword ascii
    $s3  = "function woapCtyvriOosInNB(KAbLN){VUsANXOGYsL= o[1803];for(iqtSkuMFQNj=Math.round((Math.pow(Math.sin(496), 2) + Math.pow(Math.co" ascii
    $s4  = "function woapCtyvriOosInNB(KAbLN){VUsANXOGYsL= o[1803];for(iqtSkuMFQNj=Math.round((Math.pow(Math.sin(496), 2) + Math.pow(Math.co" ascii
    $s5  = "neUC)) {return (String.fromCharCode(VrikgwEJuFzgneUC) + String.fromCharCode((33714+243)/693));}}" fullword ascii
    $s6  = "function I(mLkoDkFXXvrW,uzuQSavHptAcmu){mLkoDkFXXvrW.push(uzuQSavHptAcmu);}function v6(VrikgwEJuFzgneUC){if(cKjlvAJ(VrikgwEJuFzg" ascii
    $s7  = "function cKjlvAJ(KjDhHnJTBWdmOKNrPoCsnBRlPGgWStFxrddL) {return !isNaN(parseFloat(KjDhHnJTBWdmOKNrPoCsnBRlPGgWStFxrddL)) && isFin" ascii
    $s8  = "function cKjlvAJ(KjDhHnJTBWdmOKNrPoCsnBRlPGgWStFxrddL) {return !isNaN(parseFloat(KjDhHnJTBWdmOKNrPoCsnBRlPGgWStFxrddL)) && isFin" ascii
    $s9  = "function UvrDvFeGMxlotbXCxetOOJalPbaKaNTaMLLARttUHokMKwBUkqFFyC(bmJDQTEDEOjeo,IjrIXVCkqHxSkM){ return WMyJFeV[VPKmyXQI[ddmqt(bmJ" ascii
    $s10 = "function ddmqt(TeFQwUsuwfT,RRLYswuhLWvpB,NDUfEMsx){KFny=parseInt(TeFQwUsuwfT,RRLYswuhLWvpB);wyeKT=KFny.toString(NDUfEMsx);return" ascii
    $s11 = "function I(mLkoDkFXXvrW,uzuQSavHptAcmu){mLkoDkFXXvrW.push(uzuQSavHptAcmu);}function v6(VrikgwEJuFzgneUC){if(cKjlvAJ(VrikgwEJuFzg" ascii
    $s12 = " wyeKT;}function OdvXNxJgkGMgyea(oDVDubGUTKyZcbqjE,XUmFWOqnXOoyGkQyCsHKDqSoWyZOnZsIOJ,svcExjteirmywlSXcyZogdksLkxnbEkzMIw){eval(" ascii
    $s13 = "function bcIutGxtaPq(pYttkMsG,LHchrg){return pYttkMsG.split(LHchrg)}" fullword ascii
    $s14 = "function ddmqt(TeFQwUsuwfT,RRLYswuhLWvpB,NDUfEMsx){KFny=parseInt(TeFQwUsuwfT,RRLYswuhLWvpB);wyeKT=KFny.toString(NDUfEMsx);return" ascii
    $s15 = "function OdvXNxJgkGMgyea(oDVDubGUTKyZcbqjE){eval(oDVDubGUTKyZcbqjE)}" fullword ascii
    $s16 = "function UvrDvFeGMxlotbXCxetOOJalPbaKaNTaMLLARttUHokMKwBUkqFFyC(bmJDQTEDEOjeo,IjrIXVCkqHxSkM){ return WMyJFeV[VPKmyXQI[ddmqt(bmJ" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}