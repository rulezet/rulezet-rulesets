rule sig_20151215_645523459271ddcdd710aa3f1375f43e {
  meta:
    description = "datamaliciousorder - file 20151215_645523459271ddcdd710aa3f1375f43e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2154250eb3cb7b119708e15b8dfacfcb2778606833b989eab7882d77a075530"

  strings:
    $s1  = "function UjUGgrUQAWgRZBPwu(wNBME){rxwDHrHnwmZ= l[1811];for(isgAEytRtuc=Math.round((Math.pow(Math.sin(42), 2) + Math.pow(Math.cos" ascii
    $s2  = "ow(Math.cos(911), 2) - 1)));} WDxWKZqyT[isgAEytRtuc]++;}} return rxwDHrHnwmZ}" fullword ascii
    $s3  = "h.pow(Math.cos(874), 2) - 1)); while(true) { if(WDxWKZqyT[isgAEytRtuc] > wNBME[isgAEytRtuc].length-(340+153)/493) { break; } if " ascii
    $s4  = "function UjUGgrUQAWgRZBPwu(wNBME){rxwDHrHnwmZ= l[1811];for(isgAEytRtuc=Math.round((Math.pow(Math.sin(42), 2) + Math.pow(Math.cos" ascii
    $s5  = "function Z(CiDcXpMUwCTX,cSduNtnAzvhgMc){CiDcXpMUwCTX.push(cSduNtnAzvhgMc);}function p6(QYUgjAyciwBICpQz){if(AmEhfBj(QYUgjAyciwBI" ascii
    $s6  = "CpQz)) {return (String.fromCharCode(QYUgjAyciwBICpQz) + String.fromCharCode((48832+395)/807));}}" fullword ascii
    $s7  = "function AmEhfBj(ksxulMAgNPIIXhYzKSreMpjwLBTnGvNJvpEX) {return !isNaN(parseFloat(ksxulMAgNPIIXhYzKSreMpjwLBTnGvNJvpEX)) && isFin" ascii
    $s8  = "function AmEhfBj(ksxulMAgNPIIXhYzKSreMpjwLBTnGvNJvpEX) {return !isNaN(parseFloat(ksxulMAgNPIIXhYzKSreMpjwLBTnGvNJvpEX)) && isFin" ascii
    $s9  = " mjfXm;}function UVNQKkbvaEIVEBu(tZsvXmpxlKezPbRJj,DsjXdKlxgdxZxzDadVOUcgwmYDVfXRVYOe,SoFgXeeyIrGeZffznuaAloaHMDtmUiyuLmy){eval(" ascii
    $s10 = "function Z(CiDcXpMUwCTX,cSduNtnAzvhgMc){CiDcXpMUwCTX.push(cSduNtnAzvhgMc);}function p6(QYUgjAyciwBICpQz){if(AmEhfBj(QYUgjAyciwBI" ascii
    $s11 = "function SRmOb(ZwOLizTJwky,pBHzhumRSFCYX,PwdRHqFE){egeZ=parseInt(ZwOLizTJwky,pBHzhumRSFCYX);mjfXm=egeZ.toString(PwdRHqFE);return" ascii
    $s12 = "function UVNQKkbvaEIVEBu(tZsvXmpxlKezPbRJj){eval(tZsvXmpxlKezPbRJj)}" fullword ascii
    $s13 = "function SRmOb(ZwOLizTJwky,pBHzhumRSFCYX,PwdRHqFE){egeZ=parseInt(ZwOLizTJwky,pBHzhumRSFCYX);mjfXm=egeZ.toString(PwdRHqFE);return" ascii
    $s14 = "function gwmHrKrozIG(snzQNbNX,MDUmIh){return snzQNbNX.split(MDUmIh)}" fullword ascii
    $s15 = "function aNMaGntyLCIJYuSMPFsJJEpYzqRkRUQCyesgPpHhZKIkcqrPvLuwNB(HoUEiSteuNZuW,NdLgZvxHmwlZVk){ return JUAhkNy[kBeIYBJa[SRmOb(HoU" ascii
    $s16 = "function aNMaGntyLCIJYuSMPFsJJEpYzqRkRUQCyesgPpHhZKIkcqrPvLuwNB(HoUEiSteuNZuW,NdLgZvxHmwlZVk){ return JUAhkNy[kBeIYBJa[SRmOb(HoU" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}