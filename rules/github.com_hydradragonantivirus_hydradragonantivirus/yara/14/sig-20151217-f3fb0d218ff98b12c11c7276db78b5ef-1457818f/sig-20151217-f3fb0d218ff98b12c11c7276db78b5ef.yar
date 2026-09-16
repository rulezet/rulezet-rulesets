rule sig_20151217_f3fb0d218ff98b12c11c7276db78b5ef {
  meta:
    description = "datamaliciousorder - file 20151217_f3fb0d218ff98b12c11c7276db78b5ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba1ed81b1b65dccd104d30fad160df4e4e61a76735a469f61054f24584de24a1"

  strings:
    $s1  = ") - 1));while(true){if (KgIBYZiPUYZ >= (4488+336)/804){break;}TxPiYixmM[KgIBYZiPUYZ]=Math.round((Math.pow(Math.sin(259), 2) + Ma" ascii
    $s2  = "pow(Math.cos(628), 2) - 1)));} TxPiYixmM[KgIBYZiPUYZ]++;}KgIBYZiPUYZ++;} return OFMcfHastpd}" fullword ascii
    $s3  = "th.pow(Math.cos(259), 2) - 1)); while(true) { if(TxPiYixmM[KgIBYZiPUYZ] > PUvDV[KgIBYZiPUYZ].length-(-167+324)/157) { break; } i" ascii
    $s4  = "function GEweIAdSMTTjAsiMK(PUvDV){OFMcfHastpd= '';KgIBYZiPUYZ=Math.round((Math.pow(Math.sin(932), 2) + Math.pow(Math.cos(932), 2" ascii
    $s5  = "UstMYtzwrlCEJHeLPepeGUJiwEkYDJfBPXA([PUvDV[KgIBYZiPUYZ][TxPiYixmM[KgIBYZiPUYZ]]], Math.round((Math.pow(Math.sin(628), 2) + Math." ascii
    $s6  = "function GEweIAdSMTTjAsiMK(PUvDV){OFMcfHastpd= '';KgIBYZiPUYZ=Math.round((Math.pow(Math.sin(932), 2) + Math.pow(Math.cos(932), 2" ascii
    $s7  = "function ALZlhUQ(DCDDlWACrJxxkSjaRAfdzJvbrPstKdtHyJfC) {return !ZkdSxfNdlXh(qHlEDChxmwgNJHm(DCDDlWACrJxxkSjaRAfdzJvbrPstKdtHyJfC" ascii
    $s8  = "var H = new Array();H[0]=[];H[0][0]='d';H[0][1]='a';H[0][2]='d';H[0][3]='a';H[0][4]='46';H[0][5]='3d';H[0][6]='42';H[0][7]='14';" ascii
    $s9  = "I);return Pwuro;}" fullword ascii
    $s10 = "function XjUOMRfaBxhO(pSLHpYSWLoZiv) {return isFinite(pSLHpYSWLoZiv);}" fullword ascii
    $s11 = "function AIfWv(dsGtelbzWnq,fbnnGJPGYWnrI,VjLhJJvI){hywq=zVPLDZHaAilTDPXnu(dsGtelbzWnq,fbnnGJPGYWnrI);Pwuro=hywq.toString(VjLhJJv" ascii
    $s12 = "function ZkdSxfNdlXh(beTCJLrjMKmreE) {return isNaN(beTCJLrjMKmreE);}" fullword ascii
    $s13 = "function b(sgWzOSIZThDggD,ytIhBehSpUUbf,rYLJWMmdqCb) {sgWzOSIZThDggD[ytIhBehSpUUbf]=rYLJWMmdqCb;}" fullword ascii
    $s14 = "function qHlEDChxmwgNJHm(YPtpprdHQpbBUPtKMtK) {return parseFloat(YPtpprdHQpbBUPtKMtK);}" fullword ascii
    $s15 = "var H = new Array();H[0]=[];H[0][0]='d';H[0][1]='a';H[0][2]='d';H[0][3]='a';H[0][4]='46';H[0][5]='3d';H[0][6]='42';H[0][7]='14';" ascii
    $s16 = "function zVPLDZHaAilTDPXnu(kTZHebqgKT,isNloQAbrU) {return parseInt(kTZHebqgKT,isNloQAbrU);}" fullword ascii
    $s17 = "function AIfWv(dsGtelbzWnq,fbnnGJPGYWnrI,VjLhJJvI){hywq=zVPLDZHaAilTDPXnu(dsGtelbzWnq,fbnnGJPGYWnrI);Pwuro=hywq.toString(VjLhJJv" ascii
    $s18 = "function F(zTwwxuRKkRSp,sberJzLpWxAwfl){zTwwxuRKkRSp.push(sberJzLpWxAwfl);}" fullword ascii
    $s19 = "function ALZlhUQ(DCDDlWACrJxxkSjaRAfdzJvbrPstKdtHyJfC) {return !ZkdSxfNdlXh(qHlEDChxmwgNJHm(DCDDlWACrJxxkSjaRAfdzJvbrPstKdtHyJfC" ascii
    $s20 = "function KkuTjBvOmGSnrML(XZMhrucMBuAbvzIvL,SZRdOzRcAFoEWBZdaHFdzRjqJEUPWxRzqD,EqAGRtvWrvzAgxwvNvnOTVxhQCLqnWbzSYj){eval(XZMhrucM" ascii

  condition:
    uint16(0) == 0x6447 and
    8 of them
}