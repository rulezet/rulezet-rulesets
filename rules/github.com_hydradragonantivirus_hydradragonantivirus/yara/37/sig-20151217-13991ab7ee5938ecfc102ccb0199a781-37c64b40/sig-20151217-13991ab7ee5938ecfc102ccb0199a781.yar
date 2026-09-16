rule sig_20151217_13991ab7ee5938ecfc102ccb0199a781 {
  meta:
    description = "datamaliciousorder - file 20151217_13991ab7ee5938ecfc102ccb0199a781.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59a05ab4bd7e6bdb5ae5d463d88f68e3e589aae1e7dbac14f78c78def6a3c2b7"

  strings:
    $s1  = "function vNPaKJMbSWRQlTDGv(AJOmC){WxXwjJeYOyM= '';RRRZUSVAkKv=Math.round((Math.pow(Math.sin(612), 2) + Math.pow(Math.cos(612), 2" ascii
    $s2  = "h.pow(Math.cos(137), 2) - 1)); while(true) { if(THixDOdNN[RRRZUSVAkKv] > AJOmC[RRRZUSVAkKv].length-(-32+323)/291) { break; } if " ascii
    $s3  = ") - 1));while(true){if (RRRZUSVAkKv >= (644+628)/212){break;}THixDOdNN[RRRZUSVAkKv]=Math.round((Math.pow(Math.sin(137), 2) + Mat" ascii
    $s4  = "(Math.cos(454), 2) - 1)));} THixDOdNN[RRRZUSVAkKv]++;}RRRZUSVAkKv++;} return WxXwjJeYOyM}" fullword ascii
    $s5  = "function vNPaKJMbSWRQlTDGv(AJOmC){WxXwjJeYOyM= '';RRRZUSVAkKv=Math.round((Math.pow(Math.sin(612), 2) + Math.pow(Math.cos(612), 2" ascii
    $s6  = "function QNLBKuR(ebhjXlSiGnFMgLOpbDzUuxsKCYhXBcglYLtk) {return !BNiwMNAgHgi(SsfzeiqBqHarIhH(ebhjXlSiGnFMgLOpbDzUuxsKCYhXBcglYLtk" ascii
    $s7  = "var W = new Array();W[0]=[];W[0][0]='d';W[0][1]='a';W[0][2]='d';W[0][3]='a';W[0][4]='46';W[0][5]='3d';W[0][6]='42';W[0][7]='14';" ascii
    $s8  = "A);return JVFKo;}" fullword ascii
    $s9  = "var W = new Array();W[0]=[];W[0][0]='d';W[0][1]='a';W[0][2]='d';W[0][3]='a';W[0][4]='46';W[0][5]='3d';W[0][6]='42';W[0][7]='14';" ascii
    $s10 = "function L(HNOivoOCgesQ,XXrcYOIkVDHzhg){HNOivoOCgesQ.push(XXrcYOIkVDHzhg);}" fullword ascii
    $s11 = "function qnZicsbjlNvZ(sSLhFvkWUbZCP) {return isFinite(sSLhFvkWUbZCP);}" fullword ascii
    $s12 = "function PkiHuXHAhFdVfoWhmCNIErXinrKDePbMPnIJRWejCdaSRXCghsBWKZ(djgliFWIkKibv,NwXFONCZzkbxIc){ return SSsplNZ[eqdQkNhI[Leolg(djg" ascii
    $s13 = "function qIhDySdxiXmEXwa(XYWBzyQhuFtnRmccE,DoBgjyeKkyhxeKgfvoDNcRqECFUIzHrROU,UPWNHjwijFrfkbPDAYfMyhLVoWRQtoPzLre){eval(XYWBzyQh" ascii
    $s14 = "function QNLBKuR(ebhjXlSiGnFMgLOpbDzUuxsKCYhXBcglYLtk) {return !BNiwMNAgHgi(SsfzeiqBqHarIhH(ebhjXlSiGnFMgLOpbDzUuxsKCYhXBcglYLtk" ascii
    $s15 = "function BNiwMNAgHgi(VJPIbVLuhwbmIB) {return isNaN(VJPIbVLuhwbmIB);}" fullword ascii
    $s16 = "function s(pkgTUHQcRqDToW,XgnaabwMJCtrk,sbCpxcQIEgj) {pkgTUHQcRqDToW[XgnaabwMJCtrk]=sbCpxcQIEgj;}" fullword ascii
    $s17 = "function qIhDySdxiXmEXwa(XYWBzyQhuFtnRmccE,DoBgjyeKkyhxeKgfvoDNcRqECFUIzHrROU,UPWNHjwijFrfkbPDAYfMyhLVoWRQtoPzLre){eval(XYWBzyQh" ascii
    $s18 = "function SsfzeiqBqHarIhH(dJfbhmTqgKauJkpOnWs) {return parseFloat(dJfbhmTqgKauJkpOnWs);}" fullword ascii
    $s19 = "function PkiHuXHAhFdVfoWhmCNIErXinrKDePbMPnIJRWejCdaSRXCghsBWKZ(djgliFWIkKibv,NwXFONCZzkbxIc){ return SSsplNZ[eqdQkNhI[Leolg(djg" ascii
    $s20 = "function Leolg(MytMdIPNVfG,RGEnnzytKwAMo,ESlYmErA){ZTWb=wWGVQlpeHyjebtOhg(MytMdIPNVfG,RGEnnzytKwAMo);JVFKo=ZTWb.toString(ESlYmEr" ascii

  condition:
    uint16(0) == 0x7165 and
    8 of them
}