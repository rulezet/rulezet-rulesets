rule sig_20151217_2dc88eec3c08115cee4958e57f8ef967 {
  meta:
    description = "datamaliciousorder - file 20151217_2dc88eec3c08115cee4958e57f8ef967.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6006bb704f17f5c04fc8c9098fd126de2fd70fcff0dc61c4719a1c46bc15c8e6"

  strings:
    $s1  = ") - 1));while(true){if (hMERqOnyMhX >= (3938+160)/683){break;}ksXBzFBRu[hMERqOnyMhX]=Math.round((Math.pow(Math.sin(702), 2) + Ma" ascii
    $s2  = "ow(Math.cos(359), 2) - 1)));} ksXBzFBRu[hMERqOnyMhX]++;}hMERqOnyMhX++;} return nKbSsLJsMMx}" fullword ascii
    $s3  = "th.pow(Math.cos(702), 2) - 1)); while(true) { if(ksXBzFBRu[hMERqOnyMhX] > wzuqd[hMERqOnyMhX].length-(-37+514)/477) { break; } if" ascii
    $s4  = "function DvtSAwyLxThyOLNzk(wzuqd){nKbSsLJsMMx= '';hMERqOnyMhX=Math.round((Math.pow(Math.sin(549), 2) + Math.pow(Math.cos(549), 2" ascii
    $s5  = "function DvtSAwyLxThyOLNzk(wzuqd){nKbSsLJsMMx= '';hMERqOnyMhX=Math.round((Math.pow(Math.sin(549), 2) + Math.pow(Math.cos(549), 2" ascii
    $s6  = "function wyWjCMz(bKGRRGdJlOCDrfmHGgDbqJYbkdoQFOGmQKkP) {return !gnJPhnPIHDo(wlSRAkxnAFZXABv(bKGRRGdJlOCDrfmHGgDbqJYbkdoQFOGmQKkP" ascii
    $s7  = "var z = new Array();z[0]=[];z[0][0]='d';z[0][1]='a';z[0][2]='d';z[0][3]='a';z[0][4]='46';z[0][5]='3d';z[0][6]='42';z[0][7]='14';" ascii
    $s8  = "function SwjRbCLZZmJTaAIaeUhxAjBlLWTSpDnfNcPCKieHOtdglfqIrfICpk(NYTlcDWBpSweW,txODVOzHwuwvjU){ return QvrKwcf[eOzCRAMd[YduTo(NYT" ascii
    $s9  = "function ScIbNJsAQFUa(KLeYFrtYAXlHZ) {return isFinite(KLeYFrtYAXlHZ);}" fullword ascii
    $s10 = "function FhDbILPLWlkugBw(WIVLMOnEpSOGKBOtg,rGfLfNdfBGkGsXGEoAkgCXoZJtChOvaaHz,EUGQZwayPJcXtdsNvURNQIeVRmCYUfWgUvS){eval(WIVLMOnE" ascii
    $s11 = "function wyWjCMz(bKGRRGdJlOCDrfmHGgDbqJYbkdoQFOGmQKkP) {return !gnJPhnPIHDo(wlSRAkxnAFZXABv(bKGRRGdJlOCDrfmHGgDbqJYbkdoQFOGmQKkP" ascii
    $s12 = "function FhDbILPLWlkugBw(WIVLMOnEpSOGKBOtg,rGfLfNdfBGkGsXGEoAkgCXoZJtChOvaaHz,EUGQZwayPJcXtdsNvURNQIeVRmCYUfWgUvS){eval(WIVLMOnE" ascii
    $s13 = "V);return erJti;}" fullword ascii
    $s14 = "function U(VtsYgmwjQnma,lyTfdjtasrqwXg){VtsYgmwjQnma.push(lyTfdjtasrqwXg);}" fullword ascii
    $s15 = "function SwjRbCLZZmJTaAIaeUhxAjBlLWTSpDnfNcPCKieHOtdglfqIrfICpk(NYTlcDWBpSweW,txODVOzHwuwvjU){ return QvrKwcf[eOzCRAMd[YduTo(NYT" ascii
    $s16 = "function C(wShsvASfbdBttO,sSzNVTrhPMvDf,bDpjtQmnKlE) {wShsvASfbdBttO[sSzNVTrhPMvDf]=bDpjtQmnKlE;}" fullword ascii
    $s17 = "function YduTo(gdYNPxdNkGI,ByRgbvAGXmGtg,xTbvJvMV){MKuq=iYzeatTVnQFjYpkFT(gdYNPxdNkGI,ByRgbvAGXmGtg);erJti=MKuq.toString(xTbvJvM" ascii
    $s18 = "function iYzeatTVnQFjYpkFT(SMgkoBRjcI,mgqLWmAqRX) {return parseInt(SMgkoBRjcI,mgqLWmAqRX);}" fullword ascii
    $s19 = "function YduTo(gdYNPxdNkGI,ByRgbvAGXmGtg,xTbvJvMV){MKuq=iYzeatTVnQFjYpkFT(gdYNPxdNkGI,ByRgbvAGXmGtg);erJti=MKuq.toString(xTbvJvM" ascii
    $s20 = "function wlSRAkxnAFZXABv(mnBfLttQWsmnBCOgHcS) {return parseFloat(mnBfLttQWsmnBCOgHcS);}" fullword ascii

  condition:
    uint16(0) == 0x4f65 and
    8 of them
}