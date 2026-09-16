rule sig_20151216_beb34b816a170d1329fbc4d6d63110fb {
  meta:
    description = "datamaliciousorder - file 20151216_beb34b816a170d1329fbc4d6d63110fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7123092bb8eeeaa0bafd0d6ae657841fd321afba886da3d424b52543d6151e61"

  strings:
    $s1  = "function SAEzQlFmjBhjDXvuy(iUAyZ){yKIcxcVRtVh= '';iXUDLZfDcpY=Math.round((Math.pow(Math.sin(911), 2) + Math.pow(Math.cos(911), 2" ascii
    $s2  = "th.pow(Math.cos(569), 2) - 1)); while(true) { if(yTWBvJohJ[iXUDLZfDcpY] > iUAyZ[iXUDLZfDcpY].length-(127+94)/221) { break; } if " ascii
    $s3  = "ow(Math.cos(834), 2) - 1)));} yTWBvJohJ[iXUDLZfDcpY]++;}iXUDLZfDcpY++;} return yKIcxcVRtVh}" fullword ascii
    $s4  = ") - 1));while(true){if (iXUDLZfDcpY >= (4559+139)/783){break;}yTWBvJohJ[iXUDLZfDcpY]=Math.round((Math.pow(Math.sin(569), 2) + Ma" ascii
    $s5  = "function SAEzQlFmjBhjDXvuy(iUAyZ){yKIcxcVRtVh= '';iXUDLZfDcpY=Math.round((Math.pow(Math.sin(911), 2) + Math.pow(Math.cos(911), 2" ascii
    $s6  = "function nXLPdNn(tTebXukqUALoTmJwvPlTWnOqJMEWIHcYpfhN) {return !oOEjAYzlBEn(UhtvEUpJPxBzWqa(tTebXukqUALoTmJwvPlTWnOqJMEWIHcYpfhN" ascii
    $s7  = "var n = new Array();n[0]=[];n[0][0]='d';n[0][1]='a';n[0][2]='d';n[0][3]='a';n[0][4]='46';n[0][5]='3d';n[0][6]='42';n[0][7]='14';" ascii
    $s8  = "function oOEjAYzlBEn(CzWHtWelRpTTqA) {return isNaN(CzWHtWelRpTTqA);}" fullword ascii
    $s9  = "function RvOal(wWfBwIPKaaV,xGgGFOESwtpku,CvHhLLhY){FGeh=VhLlRorJwZKgjplnR(wWfBwIPKaaV,xGgGFOESwtpku);KIYAn=FGeh.toString(CvHhLLh" ascii
    $s10 = "var n = new Array();n[0]=[];n[0][0]='d';n[0][1]='a';n[0][2]='d';n[0][3]='a';n[0][4]='46';n[0][5]='3d';n[0][6]='42';n[0][7]='14';" ascii
    $s11 = "function nXLPdNn(tTebXukqUALoTmJwvPlTWnOqJMEWIHcYpfhN) {return !oOEjAYzlBEn(UhtvEUpJPxBzWqa(tTebXukqUALoTmJwvPlTWnOqJMEWIHcYpfhN" ascii
    $s12 = "function YOFjPbvJkotTdnZ(szFIbcSOdOUlyJmSH,xqWgohvtNKnhQpPtbyHzOzvaGeacxhzsvS,xgREjTJnEBnUoBLJXFquLPGQbSvCEkJcwmZ){eval(szFIbcSO" ascii
    $s13 = "function YOFjPbvJkotTdnZ(szFIbcSOdOUlyJmSH,xqWgohvtNKnhQpPtbyHzOzvaGeacxhzsvS,xgREjTJnEBnUoBLJXFquLPGQbSvCEkJcwmZ){eval(szFIbcSO" ascii
    $s14 = "function pdEYImLWqxdTpLqgSEMuENaPnWIZgFEFIVnqdTJUxKVLyrIAnQbfNG(pbraeYRHTxfqJ,xvmfFlopiCLjWO){ return qzJZvvF[REAqLGmN[RvOal(pbr" ascii
    $s15 = "Y);return KIYAn;}" fullword ascii
    $s16 = "function UhtvEUpJPxBzWqa(tYSVHYigzcNUPvYDDkc) {return parseFloat(tYSVHYigzcNUPvYDDkc);}" fullword ascii
    $s17 = "function pdEYImLWqxdTpLqgSEMuENaPnWIZgFEFIVnqdTJUxKVLyrIAnQbfNG(pbraeYRHTxfqJ,xvmfFlopiCLjWO){ return qzJZvvF[REAqLGmN[RvOal(pbr" ascii
    $s18 = "function VhLlRorJwZKgjplnR(fNHlveDliy,QnXmahJTVb) {return parseInt(fNHlveDliy,QnXmahJTVb);}" fullword ascii
    $s19 = "function RvOal(wWfBwIPKaaV,xGgGFOESwtpku,CvHhLLhY){FGeh=VhLlRorJwZKgjplnR(wWfBwIPKaaV,xGgGFOESwtpku);KIYAn=FGeh.toString(CvHhLLh" ascii
    $s20 = ",']','M','4','V','\"','p','W','2','O','Z','b','X','q','3','\"','A','[','M','Y','X','w','J','h','Z','`','L','_','[','_','G',Strin" ascii

  condition:
    uint16(0) == 0x4552 and
    8 of them
}