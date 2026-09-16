rule sig_20151216_bb8e5177ebadbeeb2a5356144cb67720 {
  meta:
    description = "datamaliciousorder - file 20151216_bb8e5177ebadbeeb2a5356144cb67720.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63810a7bbee5c1272abdaa91bcadb78fdf244688f6311390faa63c4cd374388e"

  strings:
    $s1  = "ath.cos(170), 2) - 1)));} oTbLRQBPH[aZzaNqBGDwa]++;}aZzaNqBGDwa++;} return AwMHxfzJSXF}" fullword ascii
    $s2  = "ow(Math.cos(301), 2) - 1)); while(true) { if(oTbLRQBPH[aZzaNqBGDwa] > zmOxg[aZzaNqBGDwa].length-(679+224)/903) { break; } if (La" ascii
    $s3  = "function PwZAGleWdlZqVaoQB(zmOxg){AwMHxfzJSXF= '';aZzaNqBGDwa=Math.round((Math.pow(Math.sin(38), 2) + Math.pow(Math.cos(38), 2) " ascii
    $s4  = "- 1));while(true){if (aZzaNqBGDwa >= (-921+951)/5){break;}oTbLRQBPH[aZzaNqBGDwa]=Math.round((Math.pow(Math.sin(301), 2) + Math.p" ascii
    $s5  = "function PwZAGleWdlZqVaoQB(zmOxg){AwMHxfzJSXF= '';aZzaNqBGDwa=Math.round((Math.pow(Math.sin(38), 2) + Math.pow(Math.cos(38), 2) " ascii
    $s6  = "function LaLFKro(uykfRpHSHwzSShRkyCuJZjfRWCByAhGMveBp) {return !MYGSrwvrcXW(WOQdBLjSZRuFPdb(uykfRpHSHwzSShRkyCuJZjfRWCByAhGMveBp" ascii
    $s7  = "var e = new Array();e[0]=[];e[0][0]='d';e[0][1]='a';e[0][2]='d';e[0][3]='a';e[0][4]='46';e[0][5]='3d';e[0][6]='42';e[0][7]='14';" ascii
    $s8  = "function uXomfvkiVXuqQzacy(VcpPtJPKgJ,AaIaXxozKo) {return parseInt(VcpPtJPKgJ,AaIaXxozKo);}" fullword ascii
    $s9  = "function axaYEgtHUveoThKhusHpJxXjUVFyslNQDoozhYIISDGbAMPJYqVyFp(GToVGnjdtwUtw,mdHrFOTSNrjOTv){ return kVHcOdp[gOVJZemv[jpftm(GTo" ascii
    $s10 = "function axaYEgtHUveoThKhusHpJxXjUVFyslNQDoozhYIISDGbAMPJYqVyFp(GToVGnjdtwUtw,mdHrFOTSNrjOTv){ return kVHcOdp[gOVJZemv[jpftm(GTo" ascii
    $s11 = "function jpftm(TwAnRdWXWfR,QTAlVsMIpZfDP,gpHWCHyn){rOTV=uXomfvkiVXuqQzacy(TwAnRdWXWfR,QTAlVsMIpZfDP);Lbuja=rOTV.toString(gpHWCHy" ascii
    $s12 = "n);return Lbuja;}" fullword ascii
    $s13 = "function WOQdBLjSZRuFPdb(NRKYGWNDpwqlWzqclcx) {return parseFloat(NRKYGWNDpwqlWzqclcx);}" fullword ascii
    $s14 = "function MYGSrwvrcXW(TwthBPXCUUvNhQ) {return isNaN(TwthBPXCUUvNhQ);}" fullword ascii
    $s15 = "function PGwttdYNbCRR(hGGkLyNADcNub) {return isFinite(hGGkLyNADcNub);}" fullword ascii
    $s16 = "function jpftm(TwAnRdWXWfR,QTAlVsMIpZfDP,gpHWCHyn){rOTV=uXomfvkiVXuqQzacy(TwAnRdWXWfR,QTAlVsMIpZfDP);Lbuja=rOTV.toString(gpHWCHy" ascii
    $s17 = "function o(iyWLHedrUYbI,zKRXaxgtqcCUHq){iyWLHedrUYbI.push(zKRXaxgtqcCUHq);}" fullword ascii
    $s18 = "function m(vKhtWFqjNuvjHt,WhMibvicXwtch,GWZZRiEeysV) {vKhtWFqjNuvjHt[WhMibvicXwtch]=GWZZRiEeysV;}" fullword ascii
    $s19 = "function SacNSLrEhXkCVJS(ksEsluFwLZjEIVyNm,qCNRdajnJmyIrrnPDQhInSACNNYLMpKyIk,SogIAhhdAZKFqIIsmUhtjLVTWjjLflXATmH){eval(ksEsluFw" ascii
    $s20 = "function SacNSLrEhXkCVJS(ksEsluFwLZjEIVyNm,qCNRdajnJmyIrrnPDQhInSACNNYLMpKyIk,SogIAhhdAZKFqIIsmUhtjLVTWjjLflXATmH){eval(ksEsluFw" ascii

  condition:
    uint16(0) == 0x4f67 and
    8 of them
}