rule sig_20151216_f190be5dd0feab5580d3177fc7010d17 {
  meta:
    description = "datamaliciousorder - file 20151216_f190be5dd0feab5580d3177fc7010d17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3423a1c79dee2b88ae5003cca46459b8f6fcc54bb857041dd9b7cd73c80231e5"

  strings:
    $s1  = "function EuglqjKDJSdEsrafG(KNyou){lAbqgynYQHD= '';UZLfSobmPNX=Math.round((Math.pow(Math.sin(327), 2) + Math.pow(Math.cos(327), 2" ascii
    $s2  = "ow(Math.cos(653), 2) - 1)));} bWpaEPVuu[UZLfSobmPNX]++;}UZLfSobmPNX++;} return lAbqgynYQHD}" fullword ascii
    $s3  = ") - 1));while(true){if (UZLfSobmPNX >= (-344+848)/84){break;}bWpaEPVuu[UZLfSobmPNX]=Math.round((Math.pow(Math.sin(955), 2) + Mat" ascii
    $s4  = "h.pow(Math.cos(955), 2) - 1)); while(true) { if(bWpaEPVuu[UZLfSobmPNX] > KNyou[UZLfSobmPNX].length-(-322+524)/202) { break; } if" ascii
    $s5  = "function EuglqjKDJSdEsrafG(KNyou){lAbqgynYQHD= '';UZLfSobmPNX=Math.round((Math.pow(Math.sin(327), 2) + Math.pow(Math.cos(327), 2" ascii
    $s6  = "function CKqELfl(KpNplGYfUuNaWUNVOkFWwlXvZnbUzvGmQQDZ) {return !haUpxXigeAE(PlQugqsSYvKdgXB(KpNplGYfUuNaWUNVOkFWwlXvZnbUzvGmQQDZ" ascii
    $s7  = "function uWwrgHQJhlkWEpI(lkWiTvJOHMaSMVlKD,fcpkOeZnrTqPNPktFaXsCRXQKyeNdQAHih,ayFtAxyrqYTuZRUTGDerqjYvylFyhkEwESH){eval(lkWiTvJO" ascii
    $s8  = "function FVNHPkRcEtWgmlUSpHJDQMPRNsCbfKtvxCLKmbfyuhPvzcclHVqHiK(DzbSVgXSldnCw,iRRALDMHXaCNPI){ return QppUbtt[tfKXTqlx[ajJtk(Dzb" ascii
    $s9  = "function CKqELfl(KpNplGYfUuNaWUNVOkFWwlXvZnbUzvGmQQDZ) {return !haUpxXigeAE(PlQugqsSYvKdgXB(KpNplGYfUuNaWUNVOkFWwlXvZnbUzvGmQQDZ" ascii
    $s10 = "var x = new Array();x[0]=[];x[0][0]='d';x[0][1]='a';x[0][2]='d';x[0][3]='a';x[0][4]='46';x[0][5]='3d';x[0][6]='42';x[0][7]='14';" ascii
    $s11 = "function uWwrgHQJhlkWEpI(lkWiTvJOHMaSMVlKD,fcpkOeZnrTqPNPktFaXsCRXQKyeNdQAHih,ayFtAxyrqYTuZRUTGDerqjYvylFyhkEwESH){eval(lkWiTvJO" ascii
    $s12 = "function haUpxXigeAE(LFNIJvnVmvKLju) {return isNaN(LFNIJvnVmvKLju);}" fullword ascii
    $s13 = "function FVNHPkRcEtWgmlUSpHJDQMPRNsCbfKtvxCLKmbfyuhPvzcclHVqHiK(DzbSVgXSldnCw,iRRALDMHXaCNPI){ return QppUbtt[tfKXTqlx[ajJtk(Dzb" ascii
    $s14 = "Q);return UQtla;}" fullword ascii
    $s15 = "var x = new Array();x[0]=[];x[0][0]='d';x[0][1]='a';x[0][2]='d';x[0][3]='a';x[0][4]='46';x[0][5]='3d';x[0][6]='42';x[0][7]='14';" ascii
    $s16 = "function nbSiOqzFqXvi(HNHCbBnenSpxV) {return isFinite(HNHCbBnenSpxV);}" fullword ascii
    $s17 = "function PlQugqsSYvKdgXB(VpngHkqfIketcvZeTih) {return parseFloat(VpngHkqfIketcvZeTih);}" fullword ascii
    $s18 = "function X(ItJOYwWxlGLv,vgHmEXQJJbGqju){ItJOYwWxlGLv.push(vgHmEXQJJbGqju);}" fullword ascii
    $s19 = "function Z(XmNjXUGOEHvuDe,IfahcGrlVPUXm,UcXUhHApHsq) {XmNjXUGOEHvuDe[IfahcGrlVPUXm]=UcXUhHApHsq;}" fullword ascii
    $s20 = "function sCAoffQEmNLfoAwTT(ShmnorbNsw,RvhQouCkyz) {return parseInt(ShmnorbNsw,RvhQouCkyz);}" fullword ascii

  condition:
    uint16(0) == 0x6674 and
    8 of them
}