rule sig_20151217_51f3566678d81c2d282e980b9afc54b4 {
  meta:
    description = "datamaliciousorder - file 20151217_51f3566678d81c2d282e980b9afc54b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f29cddc57972d2d445a235af22097459ef414e77d130344f35228db21b165cf6"

  strings:
    $s1  = "ath.cos(303), 2) - 1)));} MgjFuyGQg[dAPNpIIecoj]++;}dAPNpIIecoj++;} return QkEZpTNZbVa}" fullword ascii
    $s2  = ".pow(Math.cos(298), 2) - 1)); while(true) { if(MgjFuyGQg[dAPNpIIecoj] > ShnBz[dAPNpIIecoj].length-(-7+281)/274) { break; } if (B" ascii
    $s3  = ") - 1));while(true){if (dAPNpIIecoj >= (5495+1)/916){break;}MgjFuyGQg[dAPNpIIecoj]=Math.round((Math.pow(Math.sin(298), 2) + Math" ascii
    $s4  = "function ptxMJQoEbqoRCwYJo(ShnBz){QkEZpTNZbVa= '';dAPNpIIecoj=Math.round((Math.pow(Math.sin(699), 2) + Math.pow(Math.cos(699), 2" ascii
    $s5  = "function ptxMJQoEbqoRCwYJo(ShnBz){QkEZpTNZbVa= '';dAPNpIIecoj=Math.round((Math.pow(Math.sin(699), 2) + Math.pow(Math.cos(699), 2" ascii
    $s6  = "function BpUdMQs(qBwTjwCnpvNzeqJZuDohAzSjngfmUCGXwkdK) {return !MndofiVkSww(QsIGrKmWXrvfdYp(qBwTjwCnpvNzeqJZuDohAzSjngfmUCGXwkdK" ascii
    $s7  = "var G = new Array();G[0]=[];G[0][0]='d';G[0][1]='a';G[0][2]='d';G[0][3]='a';G[0][4]='46';G[0][5]='3d';G[0][6]='42';G[0][7]='14';" ascii
    $s8  = "function cEToQiEoHYUPVRYSB(JVBuupgSga,pCmzjLOnyj) {return parseInt(JVBuupgSga,pCmzjLOnyj);}" fullword ascii
    $s9  = "function vZgnutiyEwZZSIv(ezGsMFPzGJvSNVgis,acMveMUCtHOFthyBBheOhhmCWezjxQHJJI,QlPdQumdofWMgaIPyImycGfVlCbIiNcEVyW){eval(ezGsMFPz" ascii
    $s10 = "E);return wozQv;}" fullword ascii
    $s11 = "function L(JyZRTXpRhsnwix,hkAWsBQlGDAcy,dyTofBbgMfl) {JyZRTXpRhsnwix[hkAWsBQlGDAcy]=dyTofBbgMfl;}" fullword ascii
    $s12 = "function MndofiVkSww(fHHQuFznuqmGKp) {return isNaN(fHHQuFznuqmGKp);}" fullword ascii
    $s13 = "function GqfNPoQEcRyU(CINlNZJxmBdNz) {return isFinite(CINlNZJxmBdNz);}" fullword ascii
    $s14 = "function BpUdMQs(qBwTjwCnpvNzeqJZuDohAzSjngfmUCGXwkdK) {return !MndofiVkSww(QsIGrKmWXrvfdYp(qBwTjwCnpvNzeqJZuDohAzSjngfmUCGXwkdK" ascii
    $s15 = "function vZgnutiyEwZZSIv(ezGsMFPzGJvSNVgis,acMveMUCtHOFthyBBheOhhmCWezjxQHJJI,QlPdQumdofWMgaIPyImycGfVlCbIiNcEVyW){eval(ezGsMFPz" ascii
    $s16 = "var G = new Array();G[0]=[];G[0][0]='d';G[0][1]='a';G[0][2]='d';G[0][3]='a';G[0][4]='46';G[0][5]='3d';G[0][6]='42';G[0][7]='14';" ascii
    $s17 = "function QsIGrKmWXrvfdYp(axUVCPIDbjEJbAPwpTw) {return parseFloat(axUVCPIDbjEJbAPwpTw);}" fullword ascii
    $s18 = "function Y(qjqMYbLUziWJ,sbGdmXBpuwgCgw){qjqMYbLUziWJ.push(sbGdmXBpuwgCgw);}" fullword ascii
    $s19 = "function eBOGRksCAbKJDcuPURhApdHpJXKnjhCOlvnmAelLhLiUiknstuBaXn(zWTljjtLEQybG,uVaXqrYgyVsqYd){ return NyiLdsp[HUcGsBEm[DmwyN(zWT" ascii
    $s20 = "function DmwyN(KbeZEsXawmK,xvMCanbEoYxSe,MinmRSPE){BtmC=cEToQiEoHYUPVRYSB(KbeZEsXawmK,xvMCanbEoYxSe);wozQv=BtmC.toString(MinmRSP" ascii

  condition:
    uint16(0) == 0x5548 and
    8 of them
}